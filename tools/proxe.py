import asyncio
import random
import threading
from concurrent.futures import ThreadPoolExecutor

import aiohttp
import requests
from bs4 import BeautifulSoup as BS
from tqdm import tqdm

from tools.user_agents import r_ua

# ---------- кэш IP пользователя ----------
_user_ip_cache = None
_user_ip_lock = threading.Lock()


def _get_real_ip(timeout=5, headers=None):
    global _user_ip_cache
    with _user_ip_lock:
        if _user_ip_cache:
            return _user_ip_cache
    try:
        r = requests.get(
            "http://icanhazip.com/",
            headers=headers or {"User-Agent": r_ua()},
            timeout=timeout,
        )
        ip = r.text.strip()
    except Exception:
        return None
    with _user_ip_lock:
        _user_ip_cache = ip
    return ip


# ---------- синхронная проверка одного прокси (старый API) ----------
def SPC(ip, port, login=None, password=None, user_ip=None, timeout=5):
    ua = r_ua()
    user_ip = user_ip or _get_real_ip(timeout=timeout, headers={"User-Agent": ua})
    if not user_ip:
        return False

    ipp = f"{ip}:{port}"
    proxy_url = f"http://{login}:{password}@{ipp}" if (login and password) else f"http://{ipp}"
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        r = requests.get(
            "http://icanhazip.com/",
            headers={"User-Agent": ua},
            proxies=proxies,
            timeout=timeout,
        )
        if r.status_code == 200 and user_ip not in r.text:
            return {"http": proxy_url} if not (login and password) else proxies
    except Exception:
        pass
    return False


# ---------- асинхронная проверка одного прокси ----------
async def _check_proxy_async(session, sem, key, ip, port, user_ip, timeout, login=None, password=None):
    async with sem:
        ipp = f"{ip}:{port}"
        proxy_url = f"http://{ipp}"
        proxy_auth = aiohttp.BasicAuth(login, password) if (login and password) else None
        try:
            async with session.get(
                "http://icanhazip.com/",
                proxy=proxy_url,
                proxy_auth=proxy_auth,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                if resp.status == 200:
                    body = (await resp.text()).strip()
                    if body and user_ip not in body:
                        shown = (
                            f"http://{login}:{password}@{ipp}"
                            if (login and password)
                            else f"http://{ipp}"
                        )
                        return key, {"ip": ip, "port": port, "format": {"http": shown, "https": shown}}
        except Exception:
            pass
        return None


class Proxy:
    def __init__(self, country=None, unknown=False, timeout=15):
        if country is None:
            country = ["ru", "by", "ua", "us"]
        if not country:
            raise ValueError("Не указаны страны")
        for ct in country:
            if ct not in ("ru", "by", "ua", "us"):
                raise ValueError(f"{ct} - неизвестная страна")
        if unknown not in (False, True):
            raise ValueError("Неизвестный параметр для unknown")
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            raise ValueError("Параметр timeout возможно указан как строка")
        if timeout < 10 or timeout > 15:
            raise ValueError("timeout не может быть меньше 10 или больше 15 секунд")

        self.unknown = unknown
        self.country = list(country)
        self.timeout = timeout
        self.list = {}
        self.list_2 = {}
        self.list_3 = {}
        self.list_4 = {}

    # ---------------- API ----------------
    def mix(self):
        if not self.list:
            return False
        return {"all": [pr for ct in self.list for pr in self.list[ct]]}

    def random(self, country=False, delete_el=False, sp=None):
        if not self.list:
            return False
        available = list(self.country)
        if self.unknown:
            available.append("unk")
        if country is not False:
            if country not in available or not self.list.get(country):
                return False
            key = country
        else:
            keys = [k for k in available if self.list.get(k)]
            if not keys:
                return False
            key = random.choice(keys)
        pr = random.choice(self.list[key])
        if delete_el:
            self.list[key].remove(pr)
        return pr

    def verify(self):
        if not self.list:
            print("Список прокси пустой")
            return

        user_ip = _get_real_ip(timeout=self.timeout)
        if not user_ip:
            print("Не удалось получить ваш IP")
            return

        items = [(key, pr["ip"], pr["port"]) for key in self.list for pr in self.list[key]]

        async def _run():
            connector = aiohttp.TCPConnector(limit=500, ttl_dns_cache=300)
            sem = asyncio.Semaphore(300)
            async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
                tasks = [
                    asyncio.create_task(
                        _check_proxy_async(session, sem, k, ip, p, user_ip, 5)
                    )
                    for k, ip, p in items
                ]
                results = []
                for fut in tqdm(
                    asyncio.as_completed(tasks),
                    total=len(tasks),
                    desc="Проверка",
                    ncols=80,
                ):
                    results.append(await fut)
                return results

        results = asyncio.run(_run())

        new_list = {}
        for res in results:
            if res is None:
                continue
            key, data = res
            new_list.setdefault(key, []).append(data)
        self.list = new_list

    def get(self):
        headers = {"User-Agent": r_ua()}

        # -------- geonode (параллельные страницы) --------
        def parse_geonode():
            itog_4 = {}
            try:
                r = requests.get(
                    "https://proxylist.geonode.com/api/proxy-list"
                    "?limit=50&page=1&sort_by=lastChecked&sort_type=desc"
                    "&speed=medium&protocols=http%2Chttps",
                    headers=headers, timeout=self.timeout,
                )
                total = r.json()["total"]
            except Exception:
                return itog_4

            per_page = 50
            col_page = max(1, (total + per_page - 1) // per_page)

            def fetch_page(i):
                try:
                    r = requests.get(
                        "https://proxylist.geonode.com/api/proxy-list"
                        f"?limit={per_page}&page={i}&sort_by=lastChecked"
                        "&sort_type=desc&speed=medium&protocols=http%2Chttps",
                        headers=headers, timeout=self.timeout,
                    )
                    if r.status_code == 200:
                        return r.json()["data"]
                except Exception:
                    pass
                return []

            with ThreadPoolExecutor(max_workers=5) as ex:
                for data in tqdm(
                    ex.map(fetch_page, range(1, col_page + 1)),
                    total=col_page, desc="geonode", ncols=80, leave=False,
                ):
                    for pr in data:
                        ct = (pr.get("country") or "").lower()
                        if ct in self.country:
                            itog_4.setdefault(ct, []).append(
                                {"ip": pr["ip"], "port": pr["port"]}
                            )
            return itog_4

        # -------- hidemy (параллельно по странам) --------
        def parse_hidemy():
            itog = {}
            url_list = {
                ct: f"https://hidemy.name/ru/proxy-list/?country={ct.upper()}&type=hs#list"
                for ct in self.country
            }

            def fetch(ct):
                try:
                    r = requests.get(url_list[ct], headers=headers, timeout=self.timeout)
                    if r.status_code != 200:
                        return ct, []
                    html = BS(r.content, "html.parser")
                    tbody = html.find("div", class_="table_block").find("tbody")
                    out = []
                    for tr in tbody:
                        tds = [td.text.replace(" ", "") for td in tr]
                        if len(tds) >= 2:
                            out.append({"ip": tds[0], "port": tds[1]})
                    return ct, out
                except Exception:
                    return ct, []

            with ThreadPoolExecutor(max_workers=max(1, len(url_list))) as ex:
                for ct, out in ex.map(fetch, list(url_list.keys())):
                    if out:
                        itog[ct] = out
            return itog

        # -------- sslproxies --------
        def parse_sslproxies():
            itog_2 = {}
            try:
                r = requests.get("https://www.sslproxies.org", headers=headers, timeout=self.timeout)
                if r.status_code != 200:
                    return itog_2
                html = BS(r.content, "html.parser")
                tbody = html.find("div", "table-responsive fpl-list").find("tbody")
                for tr in tbody:
                    tds = [td.text.strip() for td in tr]
                    if len(tds) < 3:
                        continue
                    ct = tds[2].lower()
                    if ct not in self.country:
                        continue
                    itog_2.setdefault(ct, []).append({"ip": tds[0], "port": tds[1]})
            except Exception:
                pass
            return itog_2

        # -------- proxyscrape --------
        def parse_proxyscrape():
            itog_3 = {"unk": []}
            if not self.unknown:
                return itog_3
            try:
                r = requests.get(
                    "https://api.proxyscrape.com/v2/?request=displayproxies"
                    "&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
                    headers=headers, timeout=self.timeout,
                )
                if r.status_code != 200:
                    return itog_3
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    ip, port = line.split(":", 1)
                    itog_3["unk"].append({"ip": ip, "port": port})
            except Exception:
                pass
            return itog_3

        # -------- параллельный запуск всех источников --------
        with ThreadPoolExecutor(max_workers=4) as ex:
            f1 = ex.submit(parse_geonode)
            f2 = ex.submit(parse_hidemy)
            f3 = ex.submit(parse_sslproxies)
            f4 = ex.submit(parse_proxyscrape)

            self.list_4 = f1.result()
            self.list = f2.result()
            self.list_2 = f3.result()
            self.list_3 = f4.result()

        # -------- слияние с дедупликацией --------
        def merge(target, extra):
            for key, vals in extra.items():
                if not vals:
                    continue
                bucket = target.setdefault(key, [])
                seen = {(p["ip"], p["port"]) for p in bucket}
                for p in vals:
                    if (p["ip"], p["port"]) not in seen:
                        bucket.append(p)
                        seen.add((p["ip"], p["port"]))

        merge(self.list, self.list_2)
        merge(self.list, self.list_3)
        merge(self.list, self.list_4)
