import os
import io
import hashlib
import datetime as dt
from pathlib import Path
from functools import wraps

from flask import Flask, jsonify, request, g, send_file, url_for
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

import pickle as _std_pickle
try:
    import dill as _pickle  # allows loading classes not importable by module path
except Exception:  # dill is optional
    _pickle = _std_pickle


import watermarking_utils as WMUtils
from watermarking_method import WatermarkingMethod
# from watermarking_utils import METHODS, apply_watermark, read_watermark, explore_pdf, is_watermarking_applicable, get_method


def create_app():
    app = Flask(__name__)

    # --- Config ---
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    # RMAP configuration
    app.config["RMAP_ENABLE"] = os.environ.get("RMAP_ENABLE", "0") in ("1", "true", "True")
    app.config["RMAP_CLIENT_KEYS_DIR"] = os.environ.get("RMAP_CLIENT_KEYS_DIR", "/app/rmap/clients")
    app.config["RMAP_SERVER_PRIV"] = os.environ.get("RMAP_SERVER_PRIV", "/app/rmap/server/server_private.pem")
    app.config["RMAP_SERVER_PUB"] = os.environ.get("RMAP_SERVER_PUB", "/app/rmap/server/server_public.pem")
    app.config["RMAP_SERVER_PRIV_PASSPHRASE"] = os.environ.get("RMAP_SERVER_PRIV_PASSPHRASE")
    app.config["RMAP_DOCUMENT_ID"] = os.environ.get("RMAP_DOCUMENT_ID")
    app.config["RMAP_WATERMARK_METHOD"] = os.environ.get("RMAP_WATERMARK_METHOD", "gulshan")
    app.config["RMAP_WATERMARK_KEY"] = os.environ.get("RMAP_WATERMARK_KEY", app.config["SECRET_KEY"])

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    # --- DB engine only (no Table metadata) ---
    def db_url() -> str:
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
        )

    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            eng = create_engine(db_url(), pool_pre_ping=True, future=True)
            app.config["_ENGINE"] = eng
        return eng

    # --- Helpers ---
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            return f(*args, **kwargs)
        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    # Helper to ensure a path stays under a given root
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # Ensure wm_key column exists if we use it later
    def _ensure_wm_key_column():
        try:
            with get_engine().connect() as conn:
                conn.execute(
                    text("""
                        ALTER TABLE Versions
                        ADD COLUMN wm_key VARCHAR(255) NULL
                    """)
                )
        except Exception:
            # If it already exists or fails we simply ignore
            pass

    # --- Static and health routes ---
    @app.route("/<path:filename>")
    def static_files(filename):
        return app.send_static_file(filename)

    @app.route("/")
    def home():
        return app.send_static_file("index.html")

    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    # --- Auth and user management ---

    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400

        hpw = generate_password_hash(password)

        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            return jsonify({"error": "email or login already exists"}), 409
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            return jsonify({"error": "invalid credentials"}), 401

        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        return jsonify(
            {
                "token": token,
                "token_type": "bearer",
                "expires_in": app.config["TOKEN_TTL_SECONDS"],
            }
        ), 200

    # --- Document upload and listing ---

    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        if "file" not in request.files:
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"error": "empty filename"}), 400

        fname = file.filename

        user_dir = app.config["STORAGE_DIR"] / "files" / g.user["login"]
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        final_name = request.form.get("name") or fname
        stored_name = f"{ts}__{fname}"
        stored_path = user_dir / stored_name
        file.save(stored_path)

        sha_hex = _sha256_file(stored_path)
        size = stored_path.stat().st_size

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify(
            {
                "id": int(row.id),
                "name": row.name,
                "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
                "sha256": row.sha256_hex,
                "size": int(row.size),
            }
        ), 201

    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        docs = [
            {
                "id": int(r.id),
                "name": r.name,
                "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
                "sha256": r.sha256_hex,
                "size": int(r.size),
            }
            for r in rows
        ]
        return jsonify({"documents": docs}), 200

    # --- Version listing ---

    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin AND d.id = :did
                    """),
                    {"glogin": str(g.user["login"]), "did": document_id},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [
            {
                "id": int(r.id),
                "documentid": int(r.documentid),
                "link": r.link,
                "intended_for": r.intended_for,
                "secret": r.secret,
                "method": r.method,
            }
            for r in rows
        ]
        return jsonify({"versions": versions}), 200

    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin
                    """),
                    {"glogin": str(g.user["login"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [
            {
                "id": int(r.id),
                "documentid": int(r.documentid),
                "link": r.link,
                "intended_for": r.intended_for,
                "method": r.method,
            }
            for r in rows
        ]
        return jsonify({"versions": versions}), 200

    # --- Get document and version contents ---

    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp

    @app.get("/api/get-version/<link>")
    def get_version(link: str):
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": link},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp

    # --- Delete documents ---

    @app.route("/api/delete-document", methods=["DELETE", "POST"])
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    def delete_document(document_id: int | None = None):
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )

        try:
            doc_id = str(int(document_id))
        except Exception:
            return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                query = "SELECT * FROM Documents WHERE id = " + doc_id
                row = conn.execute(text(query)).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        storage_root = Path(app.config["STORAGE_DIR"])
        file_deleted = False
        file_missing = False
        delete_error = None
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                except Exception as e:
                    delete_error = f"failed to delete file: {e}"
                    app.logger.warning(
                        "Failed to delete file %s for doc id=%s: %s",
                        fp,
                        row.id,
                        e,
                    )
            else:
                file_missing = True
        except RuntimeError as e:
            delete_error = str(e)
            app.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

        try:
            with get_engine().begin() as conn:
                conn.execute(text("DELETE FROM Documents WHERE id = :id"), {"id": doc_id})
        except Exception as e:
            return jsonify({"error": f"database error during delete: {str(e)}"}), 503

        return jsonify(
            {
                "deleted": True,
                "id": doc_id,
                "file_deleted": file_deleted,
                "file_missing": file_missing,
                "note": delete_error,
            }
        ), 200

    # --- Watermark creation and reading ---

    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        if not method or not intended_for or not isinstance(secret, str) or not isinstance(key, str):
            return jsonify({"error": "method, intended_for, secret, and key are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id
                        LIMIT 1
                    """),
                    {"id": doc_id},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        try:
            applicable = WMUtils.is_watermarking_applicable(method=method, pdf=str(file_path), position=position)
            if applicable is False:
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            return jsonify({"error": f"watermark applicability check failed: {e}"}), 400

        try:
            wm_bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position,
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                return jsonify({"error": "watermarking produced no output"}), 500
        except Exception as e:
            return jsonify({"error": f"watermarking failed: {e}"}), 500

        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        candidate = f"{base_name}__{intended_slug}.pdf"
        dest_path = dest_dir / candidate

        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            return jsonify({"error": f"failed to write watermarked file: {e}"}), 500

        link_token = hashlib.sha1(candidate.encode("utf-8")).hexdigest()

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": str(dest_path),
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except Exception as e:
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"error": f"database error during version insert: {e}"}), 503

        return jsonify(
            {
                "id": vid,
                "documentid": doc_id,
                "link": link_token,
                "intended_for": intended_for,
                "method": method,
                "position": position,
                "filename": candidate,
                "size": len(wm_bytes),
            }
        ), 201

    # GET /api/get-watermarking-methods -> {"methods":[{"name":..., "description":...}, ...], "count":N}
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []
        for m in WMUtils.METHODS:
            methods.append(
                {"name": m, "description": WMUtils.get_method(m).get_usage()}
            )
        return jsonify({"methods": methods, "count": len(methods)}), 200

    @app.post("/api/load-plugin")
    @require_auth
    def load_plugin():
        """
        Load a serialized Python class implementing WatermarkingMethod from
        STORAGE_DIR/files/plugins/<filename>.{pkl|dill} and register it in WMUtils.METHODS.
        Body: { "filename": "MyMethod.pkl", "overwrite": false }
        """
        payload = request.get_json(silent=True) or {}
        filename = (payload.get("filename") or "").strip()
        overwrite = bool(payload.get("overwrite", False))

        if not filename:
            return jsonify({"error": "filename is required"}), 400

        storage_root = Path(app.config["STORAGE_DIR"])
        plugins_dir = storage_root / "files" / "plugins"
        try:
            plugins_dir.mkdir(parents=True, exist_ok=True)
            plugin_path = plugins_dir / filename
        except Exception as e:
            return jsonify({"error": f"plugin path error: {e}"}), 500

        if not plugin_path.exists():
            return jsonify({"error": f"plugin file not found: {filename}"}), 404

        try:
            with plugin_path.open("rb") as f:
                obj = _pickle.load(f)
        except Exception as e:
            return jsonify({"error": f"failed to deserialize plugin: {e}"}), 400

        if isinstance(obj, type):
            cls = obj
        else:
            cls = obj.__class__

        method_name = getattr(cls, "name", getattr(cls, "__name__", None))
        if not method_name or not isinstance(method_name, str):
            return jsonify(
                {"error": "plugin class must define a readable name (class.__name__ or .name)"}
            ), 400

        has_api = all(hasattr(cls, attr) for attr in ("add_watermark", "read_secret"))
        if WatermarkingMethod is not None:
            is_ok = issubclass(cls, WatermarkingMethod) and has_api
        else:
            is_ok = has_api
        if not is_ok:
            return jsonify(
                {"error": "plugin does not implement WatermarkingMethod API (add_watermark/read_secret)"}
            ), 400

        # Register the class (not an instance) so you can instantiate as needed later
        WMUtils.METHODS[method_name] = cls()

        return jsonify(
            {
                "loaded": True,
                "filename": filename,
                "registered_as": method_name,
                "class_qualname": f"{getattr(cls, '__module__', '?')}."
                f"{getattr(cls, '__qualname__', cls.__name__)}",
                "methods_count": len(WMUtils.METHODS),
            }
        ), 201

    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not isinstance(key, str):
            return jsonify({"error": "method, and key are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": doc_id},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        try:
            secret = WMUtils.read_watermark(method=method, pdf=str(file_path), key=key)
        except Exception as e:
            return jsonify({"error": f"Error when attempting to read watermark: {e}"}), 400
        return jsonify(
            {
                "documentid": doc_id,
                "secret": secret,
                "method": method,
                "position": position,
            }
        ), 201

    # -------- RMAP helpers --------

    _rmap_obj = None
    _rmap_idm = None

    def _rmap_available() -> bool:
        return bool(app.config.get("RMAP_ENABLE", False))

    def _get_rmap():
        nonlocal _rmap_obj, _rmap_idm

        if _rmap_obj is not None and _rmap_idm is not None:
            return _rmap_obj, _rmap_idm

        try:
            from rmap.identity_manager import IdentityManager
            from rmap.rmap import RMAP
        except Exception as e:
            raise RuntimeError(f"RMAP library not available: {e}")

        clients_dir = Path(app.config["RMAP_CLIENT_KEYS_DIR"]).resolve()
        server_priv = Path(app.config["RMAP_SERVER_PRIV"]).resolve()
        server_pub = Path(app.config["RMAP_SERVER_PUB"]).resolve()

        if not clients_dir.exists():
            raise RuntimeError(f"RMAP clients dir not found: {clients_dir}")

        if not server_priv.exists() or not server_pub.exists():
            raise RuntimeError("RMAP server keypair not found")

        _idm = IdentityManager(
            client_keys_dir=str(clients_dir),
            server_public_key_path=str(server_pub),
            server_private_key_path=str(server_priv),
            server_private_key_passphrase=app.config.get("RMAP_SERVER_PRIV_PASSPHRASE"),
        )

        _rmap_idm = _idm
        _rmap_obj = RMAP(_idm)
        return _rmap_obj, _rmap_idm

    # -------- RMAP endpoints --------

    @app.post("/api/rmap-initiate")
    def rmap_initiate():
        if not _rmap_available():
            return jsonify({"error": "RMAP disabled"}), 404

        payload_b64 = (request.get_json(silent=True) or {}).get("payload")
        if not payload_b64 or not isinstance(payload_b64, str):
            return jsonify({"error": "payload required"}), 400

        try:
            rmap, _ = _get_rmap()
            res = rmap.handle_message1({"payload": payload_b64})

            app.logger.info(
                "rmap.message1",
                extra={"result_keys": list(res.keys()) if isinstance(res, dict) else "non-dict"},
            )

            if isinstance(res, dict) and "payload" in res:
                return jsonify({"payload": res["payload"]}), 200

            if isinstance(res, dict) and "error" in res:
                return jsonify(res), 400

            return jsonify({"error": "unexpected RMAP response"}), 500

        except Exception as e:
            app.logger.error("rmap.initiate.error", extra={"error": str(e)})
            return jsonify({"error": f"rmap initiation failed: {e}"}), 400

    @app.post("/api/rmap-get-link")
    def rmap_get_link():
        if not _rmap_available():
            return jsonify({"error": "RMAP disabled"}), 404

        payload_b64 = (request.get_json(silent=True) or {}).get("payload")
        if not payload_b64 or not isinstance(payload_b64, str):
            return jsonify({"error": "payload required"}), 400

        try:
            rmap, idm = _get_rmap()
            res = rmap.handle_message2({"payload": payload_b64})

            if isinstance(res, dict) and "error" in res:
                app.logger.info("rmap.message2.error", extra={"error": res.get("error")})
                return jsonify(res), 400

            if not (isinstance(res, dict) and "result" in res and isinstance(res["result"], str)):
                app.logger.error("rmap.message2.unexpected", extra={"got": str(res)})
                return jsonify({"error": "unexpected RMAP response"}), 500

            result_hex = res["result"].lower()

            # extract nonceServer by decrypting the payload, fallback to scanning rmap state
            try:
                obj = idm.decrypt_for_server(payload_b64)
                nonce_server = int(obj.get("nonceServer"))
            except Exception:
                nonce_server = None

            identity = None
            try:
                for ident, (_nc, ns) in dict(getattr(rmap, "nonces", {})).items():
                    if nonce_server is not None and int(ns) == int(nonce_server):
                        identity = ident
                        break
            except Exception:
                identity = None

            if identity is None:
                identity = "unknown"

            secret_hex = result_hex
            link_token = result_hex

            # Find base document that we will watermark per identity
            doc_id_env = app.config.get("RMAP_DOCUMENT_ID")
            if not doc_id_env:
                return jsonify({"error": "RMAP_DOCUMENT_ID not configured"}), 500

            try:
                base_doc_id = int(doc_id_env)
            except (TypeError, ValueError):
                return jsonify({"error": "RMAP_DOCUMENT_ID must be an integer"}), 500

            try:
                with get_engine().connect() as conn:
                    row = conn.execute(
                        text("SELECT id, name, path FROM Documents WHERE id = :id LIMIT 1"),
                        {"id": base_doc_id},
                    ).first()
            except Exception as e:
                app.logger.error(
                    "db.query.error",
                    extra={"where": "rmap_get_link.select_doc", "error": str(e)},
                )
                return jsonify({"error": f"database error: {str(e)}"}), 503

            if not row:
                return jsonify({"error": "base document not found"}), 404

            storage_root = Path(app.config["STORAGE_DIR"]).resolve()
            file_path = Path(row.path)
            if not file_path.is_absolute():
                file_path = storage_root / file_path
            file_path = file_path.resolve()

            try:
                file_path.relative_to(storage_root)
            except ValueError:
                app.logger.warning("path.escape.detected", extra={"path": str(file_path)})
                return jsonify({"error": "document path invalid"}), 500

            if not file_path.exists():
                return jsonify({"error": "file missing on disk"}), 410

            method = app.config.get("RMAP_WATERMARK_METHOD", "gulshan")
            key = app.config.get("RMAP_WATERMARK_KEY", app.config["SECRET_KEY"])

            try:
                applicable = WMUtils.is_watermarking_applicable(
                    method=method, pdf=str(file_path), position=None
                )
                if applicable is False:
                    app.logger.info(
                        "wm.inapplicable",
                        extra={"method": method, "doc": str(file_path)},
                    )
                    return jsonify({"error": "configured watermarking method not applicable"}), 400
            except Exception as e:
                app.logger.error("wm.applicability.error", extra={"error": str(e)})
                return jsonify(
                    {"error": f"watermark applicability check failed: {e}"}
                ), 400

            try:
                wm_bytes = WMUtils.apply_watermark(
                    pdf=str(file_path),
                    secret=secret_hex,
                    key=str(key),
                    method=str(method),
                    position=None,
                )
                if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                    return jsonify({"error": "watermarking produced no output"}), 500
            except Exception as e:
                app.logger.error("wm.apply.error", extra={"error": str(e)})
                return jsonify({"error": f"watermarking failed: {e}"}), 500

            base_name = Path(row.name or file_path.name).stem
            intended_slug = secure_filename(str(identity) or "recipient")
            dest_dir = file_path.parent / "watermarks"
            dest_dir.mkdir(parents=True, exist_ok=True)
            candidate = f"{base_name}__{intended_slug}.pdf"
            dest_path = dest_dir / candidate

            try:
                with dest_path.open("wb") as f:
                    f.write(wm_bytes)
            except Exception as e:
                app.logger.error(
                    "fs.write.error", extra={"path": str(dest_path), "error": str(e)}
                )
                return jsonify(
                    {"error": f"failed to write watermarked file: {e}"}
                ), 500

            try:
                _ensure_wm_key_column()
            except Exception:
                pass

            try:
                with get_engine().begin() as conn:
                    conn.execute(
                        text(
                            """
                            INSERT INTO Versions (
                                documentid, link, intended_for,
                                secret, method, wm_key, position, path
                            )
                            VALUES (
                                :documentid, :link, :intended_for,
                                :secret, :method, :wm_key, :position, :path
                            )
                            """
                        ),
                        {
                            "documentid": int(row.id),
                            "link": link_token,
                            "intended_for": str(identity),
                            "secret": secret_hex,
                            "method": str(method),
                            "wm_key": str(key),
                            "position": "",
                            "path": str(dest_path),
                        },
                    )
            except IntegrityError:
                try:
                    dest_path.unlink(missing_ok=True)
                except Exception:
                    pass
                app.logger.info("version.dup_link", extra={"link": link_token})
                return jsonify({"error": "version link already exists"}), 409
            except Exception as e:
                try:
                    dest_path.unlink(missing_ok=True)
                except Exception:
                    pass
                app.logger.error(
                    "db.insert.error",
                    extra={"table": "Versions", "error": str(e)},
                )
                return jsonify(
                    {"error": f"database error during version insert: {e}"}
                ), 503

            app.logger.info(
                "rmap.issued", extra={"identity": identity, "link": link_token}
            )
            return jsonify({"result": link_token, "link": url_for("get_version", link=link_token)}), 200

        except Exception as e:
            app.logger.error("rmap.get_link.error", extra={"error": str(e)})
            return jsonify({"error": f"rmap get-link failed: {e}"}), 400

    return app


# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)