import re
import fitz

pdf_path = "08.pdf" 

doc = fitz.open(pdf_path)

all_text = ""
for page in doc:
	all_text += page.get_text("text")

match = re.search(r"\[HWM\](.+?)\[/HWM\]", all_text)
if match:
	print("Watermark value:", match.group(1))
else:
	print("No HWM watermark found")