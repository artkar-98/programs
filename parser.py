from urllib import request, parse
import re
import sqlite3


def main():
    product = input("Enter product name:").lower()
    name_table = product
    name_table = name_table.replace(" ", "_").lower()
    if name_table == "":
        name_table = "_"
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE " + name_table + " (kla_id TEXT, name TEXT, cve_list TEXT)")

    myurl = "https://threats.kaspersky.com/en/vulnerability/"
    req = request.Request(myurl)
    response = request.urlopen(req)
    response = response.readlines()

    for num in range(2, 53):
        for i in range(0, len(response)):
            finder = re.findall(r"\s{20}" + product + r"\s{16}</a>", str(response[i]).lower())
            if finder != []:
                Kaspersky_ID = "".join(map(str,re.findall(r"KLA\d{5}", str(response[i - 8]))))
                Name = "".join(map(str, re.findall(r"\s\s.*\s\s", str(response[i - 4]))))
                Name = Name.replace("  ", "")
                href = "".join(map(str, re.findall(r"https.*KLA.*/", str(response[i - 5]))))
                req = request.Request(href)
                resp = request.urlopen(req)
                resp = resp.readlines()
                for j in range(0, len(resp)):
                    finder_href = re.findall(r"https://cve\.mitre\.org/cgi-bin/cvename\.cgi\?name=CVE-\d{4}-\d{1,6}", str(resp[j]))
                    finder_cve = re.findall(r'CVE-\d{4}-\d{1,6}"', str(resp[j]))
                    for k in range(0, len(finder_cve)):
                        finder_cve[k] = finder_cve[k].replace('"', '')
                    if finder_href != [] and finder_cve != []:
                        cve_href = dict(zip(finder_cve, finder_href))
                        cve_href = str(cve_href).replace("{", "")
                        cve_href = cve_href.replace("}", "")
                        cve_href = cve_href.replace("'", "")
                        cursor.execute("INSERT INTO " + name_table + " VALUES(?, ?, ?)", (Kaspersky_ID, Name, cve_href))
                        conn.commit()
                        print("Add to database: " + Kaspersky_ID + "," + Name + "," + cve_href)
        myurl = "https://threats.kaspersky.com/en/wp-admin/admin-ajax.php"
        data = {'action': 'infinite_scroll',
                'page_no': num,
                'post_type': 'vulnerability',
                'template': 'row_vulnerability4archive'}
        data = parse.urlencode(data)
        next_page = request.urlopen(myurl, data.encode('utf-8'))
        next_page = next_page.readlines()
        response = next_page


if __name__ == "__main__":
    main()


