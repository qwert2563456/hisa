import csv
import re

filename = "hiaka.csv"  # 確認したいCSVファイル名
email_regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

emails = []
duplicates = set()

with open(filename, newline="", encoding="utf-8") as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        for cell in row:
            cell = cell.strip()
            if re.fullmatch(email_regex, cell):
                if cell in emails:
                    duplicates.add(cell)
                else:
                    emails.append(cell)

if duplicates:
    print("重複しているメールアドレス:")
    for d in duplicates:
        print(d)
else:
    print("重複しているメールアドレスはありません。")
