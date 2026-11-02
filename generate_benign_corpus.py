"""Generate a realistic benign + blind-SQLi corpus for data/feedback/custom_traffic.csv.

The public datasets' benign rows are mostly names and addresses, so the model
scores short legitimate phrases that mix everyday words with SQL-ish tokens
(and, or, >, =, select, order, union, count) too high: "C++ and C# tutorials",
"price > 100 and rating >= 4", "1 or 2 items per customer" all scored >0.5.
This teaches a broad class of such phrases are safe, and reinforces blind-SQLi
forms (ASCII(SUBSTRING((SELECT ...)))) as attacks. Generated from templates for
breadth so it generalises rather than memorising specific strings.

    python generate_benign_corpus.py data/feedback/custom_traffic.csv
    python fetch_data.py --source github kaggle --custom data/feedback/custom_traffic.csv
    python tune.py            # retrain; then: docker compose restart ml-api openresty
"""
import csv
import itertools
import random
import sys

random.seed(7)
rows = []  # (query, label)


def add(q, label):
    rows.append((q.strip(), label))


# ---- benign (label 0) ----------------------------------------------------
techs = ["C", "C++", "C#", ".NET", "Java", "Python", "Node.js", "React", "Go", "Rust", "R",
         "VB.NET", "SQL", "Ruby", "PHP", "Swift", "Kotlin", "Scala", "Perl", "TypeScript"]
for a, b in itertools.combinations(techs, 2):
    if random.random() < 0.22:
        add(random.choice([f"{a} and {b} tutorials", f"learn {a} or {b}", f"{a} vs {b} comparison",
                           f"{a} and {b} for beginners", f"switch from {a} to {b}", f"{a} or {b} jobs"]), 0)

nouns = ["items", "colors", "people", "days", "weeks", "options", "sizes", "pairs", "units",
         "guests", "nights", "seats", "tickets", "boxes", "copies", "licenses"]
for n in nouns:
    for a, b in [(1, 2), (2, 3), (3, 4), (5, 6), (1, 3), (2, 4)]:
        add(random.choice([f"{a} or {b} {n} per customer", f"buy {a} or {b} {n}", f"pick {a} or {b} {n}",
                           f"add {a} or {b} {n} to cart", f"{a} or {b} {n} maximum", f"takes {a} or {b} {n}"]), 0)

fields = ["price", "rating", "age", "height", "width", "weight", "score", "stock", "quantity",
          "length", "size", "count", "discount", "distance", "duration"]
ops = [">", ">=", "<", "<=", "="]
for f in fields:
    for _ in range(3):
        o1, o2 = random.choice(ops), random.choice(ops)
        g = random.choice(fields)
        add(random.choice([f"{f} {o1} {random.randint(1,500)} and {g} {o2} {random.randint(1,100)}",
                           f"filter {f} {o1} {random.randint(1,200)} or {g} {o2} {random.randint(1,50)}",
                           f"show items where {f} {o1} {random.randint(1,300)}",
                           f"{f} {o1} {random.randint(1,100)} and in stock"]), 0)

sql_words_benign = [
    "select your size and color", "select a few of our best products", "select one option from the menu",
    "order by newest arrivals first", "order by price low to high", "sort or order your results",
    "drop us a line anytime", "drop by our store this weekend", "don't drop the ball on returns",
    "union made and fair trade goods", "join our rewards program", "join us for the sale",
    "count me in for the newsletter", "group discount for 10 or more", "update your shipping address",
    "delete an item from your wishlist", "insert your promo code at checkout", "we select few premium brands",
    "where do you want it shipped", "having trouble with your order", "between us, it's the best deal",
    "and or but are conjunctions", "true or false quiz", "yes and no answers only",
    "the left side of the page", "right and left shoes", "count the items in your bag",
    "left over stock on sale", "please select from the list", "a mix of old and new styles",
]
for s in sql_words_benign:
    add(s, 0)

reviews = [
    "it's a select few", "O'Brien and O'Malley", "rock 'n' roll and jazz vinyl", "can't and won't return it",
    "it's great and it's cheap", "don't buy if you want fast shipping", "won't fit and too tight",
    "5 stars and worth every penny", "it's a 9 or 10 out of 10", "it's small but it's well made",
    "fast and free and reliable", "cheap and cheerful and fun", "it's a hit or miss really",
    "would buy 1 or 2 more", "great product fast shipping would buy again", "size up or down as needed",
    "runs small so order 1 or 2 sizes up", "arrived in 2 or 3 days and well packed",
]
for s in reviews:
    add(s, 0)

misc = [
    "a < b and b < c", "x = y + z works fine", "if a and b then c", "2 + 2 = 4 and 3 + 3 = 6",
    "shoes size 9 or 10 in black or brown", "available in red and blue or green", "ships in 1 or 2 weeks",
    "https://cdn.example.com/a/../b/style.css", "email me at a.b@example.com", "call 1 or 2 times",
    "the cat sat on the mat", "price is 100 or less and free shipping", "pick up in 1 or 2 hours",
    "Q&A and FAQ section", "Tom & Jerry and friends", "50% off and free returns", "buy one and get one",
    "men and women and kids", "new and used and refurbished", "small and medium and large",
]
for s in misc:
    add(s, 0)

# ---- blind / padded SQLi (label 1) ---------------------------------------
cols = ["password", "pw", "pass", "username", "email", "credit_card", "ssn", "secret", "token"]
tbls = ["users", "accounts", "admin", "members", "customers", "u", "a"]
pad = "great product fast shipping would buy again "
for _ in range(40):
    c, t = random.choice(cols), random.choice(tbls)
    n = random.randint(1, 8)
    attacks = [
        f"1 AND ASCII(SUBSTRING((SELECT {c} FROM {t}),1,1))>{random.randint(64,120)}",
        f"1 AND ASCII(SUBSTR((SELECT {c} FROM {t} LIMIT 1),{n},1))={random.randint(97,122)}",
        f"1' AND (SELECT SUBSTRING({c},{n},1) FROM {t})='a",
        f"1 AND (SELECT COUNT(*) FROM {t})>{random.randint(0,5)}",
        f"1 AND LENGTH((SELECT {c} FROM {t} LIMIT 1))>{random.randint(1,30)}",
        f"1 AND ORD(MID((SELECT {c} FROM {t}),{n},1))>{random.randint(64,120)}",
        f"1' AND IF((SELECT SUBSTRING({c},1,1) FROM {t})='a',SLEEP(3),0)--",
        pad * random.randint(10, 30) + f" AND ASCII(SUBSTRING((SELECT {c} FROM {t}),1,1))>77",
    ]
    add(random.choice(attacks), 1)

# dedupe, write
seen, out = set(), []
for q, label in rows:
    if q and (q, label) not in seen:
        seen.add((q, label))
        out.append((q, label))

path = sys.argv[1]
with open(path, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["query", "label"])
    w.writerows(out)
benign = sum(1 for _, l in out if l == 0)
print(f"wrote {len(out)} rows ({benign} benign, {len(out)-benign} attack) to {path}")
