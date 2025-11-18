import os
import json
import hashlib
import datetime as dt
from pathlib import Path
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, request, g, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

# RMAP (v2)
from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP

import pickle as _std_pickle
try:
    import dill as _pickle  # allows loading classes not importable by module path
except Exception:
    _pickle = _std_pickle

import watermarking_utils as WMUtils
from watermarking_method import WatermarkingMethod


def create_app():
    app = Flask(__name__)

    # =========================
    # Security headers
    # =========================
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    # =========================
    # Logging
    # =========================
    log_dir = Path("./storage/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(log_dir / "server.log", maxBytes=5_000_000, backupCount=5)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    @app.before_request
    def log_request_info():
        xff = request.headers.get("X-Forwarded-For", "") or ""
        xri = request.headers.get("X-Real-IP", "") or ""
        real_ip = (xff.split(",")[0].strip() if xff else (xri or request.remote_addr))
        app.logger.info(f"ClientIP={real_ip} {request.method} {request.path}")

    # =========================
    # Config
    # =========================
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    # =========================
    # DB engine
    # =========================
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

    # =========================
    # RMAP init (ONE instance)
    # =========================
    try:
        app.logger.info("Initializing RMAP...")
        clients_dir = "/app/server/src/rmap/pki/clients"
        server_pub = "/app/server/src/rmap/pki/server_pub.asc"
        server_priv = "/app/server/src/rmap/pki/server_priv.asc"
        im = IdentityManager(clients_dir, server_pub, server_priv)
        app.config["_RMAP"] = RMAP(im)
        app.logger.info("RMAP successfully initialized.")
    except Exception as e:
        app.logger.error(f"Failed to initialize RMAP: {e}")
        app.config["_RMAP"] = None

    # =========================
    # Helpers
    # =========================
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

    # =========================
    # Base routes
    # =========================
    @app.route("/")
    def home():
        return jsonify({"message": "Tatou Server Running"}), 200

    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"message": "Server is running", "db_connected": db_ok}), 200

    # ===========================================
# RMAP HANDSHAKE ENDPOINTS
# ===========================================

   @app.post("/api/rmap-initiate")
   def rmap_initiate():
    """
    Step 1 of the RMAP protocol:
    Accepts RMAP Message 1 (encrypted payload), validates
    the identity against known public keys, and returns Response 1.
    """
    app.logger.info("RMAP: Received initiation request")

    if app.config.get("_RMAP") is None:
        return jsonify({"error": "RMAP not initialized"}), 500

    msg = request.get_json(silent=True) or {}
    if not isinstance(msg, dict) or not msg.get("payload"):
        return jsonify({"error": "missing payload"}), 400

    try:
        # Handle first RMAP message (nonceClient, identity)
        resp1 = app.config["_RMAP"].handle_message1(msg)
        app.logger.info("RMAP: Message 1 processed successfully")
        return jsonify(resp1), 200

    except Exception as e:
        app.logger.error(f"RMAP initiation error: {e}")
        return jsonify({"error": f"RMAP initiation error: {e}"}), 400

    @app.post("/api/rmap-get-link")
def rmap_get_link():
    """
    Step 2 of the RMAP protocol:
    Accepts RMAP Message 2 (encrypted payload) and returns a secret link.
    The server watermarks a PDF with that secret and records the entry in the database.
    """
    app.logger.info("RMAP: Received get-link request")

    # -------------------------------
    # Extract payload
    # -------------------------------
    payload = (request.get_json(silent=True) or {}).get("payload")
    if not payload:
        return jsonify({"error": "missing payload"}), 400

    # -------------------------------
    # Get active RMAP instance
    # -------------------------------
    rmap = app.config.get("_RMAP")
    if rmap is None:
        app.logger.error("RMAP instance not initialized")
        return jsonify({"error": "RMAP not initialized"}), 500

    try:
        # -------------------------------
        # Handle Message 2 (compatibility-safe)
        # -------------------------------
        response = rmap.handle_message2({"payload": payload})
        if isinstance(response, tuple):
            result, identity = response
        else:
            result = response
            identity = "unknown"

        secret_link = result.get("result") if isinstance(result, dict) else result
        if not secret_link:
            raise ValueError("Failed to generate secret link")

        app.logger.info(f"RMAP: identity={identity or 'unknown'}, link={secret_link}")

        # -------------------------------
        # Apply watermark to base PDF
        # -------------------------------
        base_pdf = "/app/server/src/rmap/base_document.pdf"  # Teacher-provided document
        wm_bytes = WMUtils.apply_watermark(
            pdf=base_pdf,
            secret=secret_link,
            key="rmap-session",
            method="metadata",
        )

        # -------------------------------
        # Save new watermarked version
        # -------------------------------
        downloads_dir = Path("/home/lab/Tatou-2/tatou/downloads")
        downloads_dir.mkdir(parents=True, exist_ok=True)
        out_path = downloads_dir / f"{identity or 'unknown'}_{secret_link}.pdf"
        with out_path.open("wb") as f:
            f.write(wm_bytes)
        app.logger.info(f"Saved watermarked PDF: {out_path}")

        # -------------------------------
        # Database entry (Versions table)
        # -------------------------------
        try:
            with get_engine().begin() as conn:
                documentid = 65  # The teacher-provided base document

                conn.execute(text("""
                    INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                    VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                """), {
                    "documentid": documentid,
                    "link": secret_link,
                    "intended_for": identity or "unknown",
                    "secret": secret_link,
                    "method": "metadata",
                    "position": "",
                    "path": str(out_path)
                })

            app.logger.info(f"RMAP: Stored watermarked PDF entry for {identity or 'unknown'} (documentid={documentid})")

        except Exception as db_err:
            app.logger.error(f"Database insert failed: {db_err}")

        # -------------------------------
        # Return encrypted or plaintext response
        # -------------------------------
        try:
            if hasattr(rmap, "encrypt_for_identity"):
                enc_response = rmap.encrypt_for_identity(identity, json.dumps({"result": secret_link}))
                return jsonify({"payload": enc_response}), 200
            else:
                app.logger.warning("Encrypt reply failed, returning plaintext")
                return jsonify({"result": secret_link}), 200
        except Exception as e:
            app.logger.warning(f"Encryption failed, returning plaintext: {e}")
            return jsonify({"result": secret_link}), 200

    except Exception as e:
        app.logger.error(f"RMAP link generation error: {e}")
        return jsonify({"error": f"RMAP link generation error: {e}"}), 400
    # =========================
    # User & Document routes
    # =========================
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
            app.logger.error(f"Database error during user creation: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        app.logger.info(f"New user created: {login}")
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
            app.logger.error(f"Database error during login: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            app.logger.warning(f"Failed login attempt for {email}")
            return jsonify({"error": "invalid credentials"}), 401

        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        app.logger.info(f"User logged in: {email}")
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

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

        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

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

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200

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

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
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

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200

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
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if str(row.name).lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,
        )
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())
        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp

    @app.get("/api/get-version/<link>")
    def get_version(link: str):
        # Try DB record first
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT link, path FROM Versions WHERE link = :link LIMIT 1"),
                    {"link": link},
                ).first()
        except Exception:
            row = None

        if row:
            file_path = Path(row.path)
        else:
            # Fallback: look in downloads
            download_dir = Path("/home/lab/Tatou-2/tatou/downloads")
            matches = list(download_dir.glob(f"*_{link}.pdf"))
            file_path = matches[0] if matches else None

        if not file_path or not file_path.exists():
            return jsonify({"error": "document not found"}), 404

        return send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=file_path.name,
            conditional=True,
        )

    # =========================
    # Safe path helper
    # =========================
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        try:
            fp.relative_to(storage_root)
        except Exception:
            raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

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
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(text("SELECT * FROM Documents WHERE id = :id"), {"id": doc_id}).first()
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
                    app.logger.warning("Failed to delete file %s for doc id=%s: %s", fp, row.id, e)
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

        return jsonify({
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
            "note": delete_error,
        }), 200

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
                    text("SELECT id, name, path FROM Documents WHERE id = :id LIMIT 1"),
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
            applicable = WMUtils.is_watermarking_applicable(
                method=method,
                pdf=str(file_path),
                position=position
            )
            if applicable is False:
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            return jsonify({"error": f"watermark applicability check failed: {e}"}), 400

        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position
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
                        "path": str(dest_path)
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except Exception as e:
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"error": f"database error during version insert: {e}"}), 503

        return jsonify({
            "id": vid,
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "method": method,
            "position": position,
            "filename": candidate,
            "size": len(wm_bytes),
        }), 201

    @app.post("/api/load-plugin")
    @require_auth
    def load_plugin():
        payload = request.get_json(silent=True) or {}
        filename = (payload.get("filename") or "").strip()
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

        cls = obj if isinstance(obj, type) else obj.__class__
        method_name = getattr(cls, "name", getattr(cls, "__name__", None))
        if not method_name or not isinstance(method_name, str):
            return jsonify({"error": "plugin class must define a readable name"}), 400

        has_api = all(hasattr(cls, attr) for attr in ("add_watermark", "read_secret"))
        if WatermarkingMethod is not None:
            is_ok = issubclass(cls, WatermarkingMethod) and has_api
        else:
            is_ok = has_api
        if not is_ok:
            return jsonify({"error": "plugin does not implement WatermarkingMethod API"}), 400

        WMUtils.METHODS[method_name] = cls()

        return jsonify({
            "loaded": True,
            "filename": filename,
            "registered_as": method_name,
            "class_qualname": f"{getattr(cls, '__module__', '?')}.{getattr(cls, '__qualname__', cls.__name__)}",
            "methods_count": len(WMUtils.METHODS)
        }), 201

    return app


# WSGI entry
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
