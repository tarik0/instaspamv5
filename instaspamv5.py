import os
from argparse import Action, ArgumentParser, Namespace
from datetime import datetime
from json import loads
from random import choice
from sys import stderr
from threading import Lock, Thread, Event

from requests import Session
from random_user_agent.user_agent import UserAgent

__author__ = "Hichigo, R35"
__version__ = "v5"

""" Global vars. """
ARGS = None
USERS, THREADS = [], []
USER_LOCK, END_EVENT = Lock(), Event()


class Logger:
    LOG_LOCK = Lock()

    @staticmethod
    def log(msg, thread_index=None):
        """ Log custom message. """
        date_str = datetime.now().strftime("%d.%m.%Y %H:%M")
        with Logger.LOG_LOCK:
            if thread_index:
                print(f"[{date_str}] [THREAD: {thread_index}] {msg}")
            else:
                print(f"[{date_str}] {msg}")


class AuthException(Exception):
    """ Thrown when authentication is failed or there is no authentication. """
    pass


class Reasons:
    """ Reporting causes. """
    SPAM = 1


class IGClient:
    """
    IGClient:
        A basic class to connect to the Instagram.
    """

    def __init__(self, proxy=None):
        """ Construct the class. """
        self.__session, self.__user_agent = Session(), UserAgent().get_random_user_agent()
        self.__session.headers.update({"User-Agent": self.__user_agent})

        # Set proxy to the session.
        if proxy:
            self.__session.proxies = self.__format_proxy(proxy)

        self.__is_authenticated = False
        self.__username, self.__password, self.__user_id = None, None, None

    def login(self, username: str, password: str):
        """ Connect to Instagram and login. """
        # Send a GET request to get required headers and cookies.
        res = self.__session.get("https://www.instagram.com/accounts/login/")
        if res.status_code != 200:
            raise res.raise_for_status()

        # Update the headers.
        self.__session.headers.update({
            "X-CSRFToken": self.__session.cookies.get("csrftoken"),
            "X-Requested-With": "XMLHttpRequest"
        })

        # Send the login request.
        res = self.__session.post("https://www.instagram.com/accounts/login/ajax/", data={
            "username": username,
            "enc_password": f"#PWD_INSTAGRAM:0:{datetime.now().timestamp()}:{password}",
            "queryParams": "{}",
            "optIntoOneTap": False
        })
        if res.status_code != 200:
            raise res.raise_for_status()

        # Get request response.
        tmp = res.json()
        if not tmp["authenticated"]:
            raise AuthException()

        # Set properties.
        self.__username, self.__password = username, password
        self.__user_id = tmp["userId"]
        self.__is_authenticated = True
        return tmp

    def report_user(self, username: str, reason: Reasons):
        """ Report an user. """
        if not self.__is_authenticated:
            raise AuthException("Session is not authenticated!")

        # Update the headers.
        self.__session.headers.update({
            "X-CSRFToken": self.__session.cookies.get("csrftoken"),
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"https://www.instagram.com/{username}/"
        })

        # Get target user's data.
        res = self.__session.get(f"https://www.instagram.com/{username}/?__a=1")
        if res.status_code != 200:
            raise res.raise_for_status()

        # Parse the JSON data.
        target_data = res.json()
        target_user_id = int(target_data["graphql"]["user"]["id"])

        # Click report.
        res = self.__session.post(f"https://www.instagram.com/reports/web/get_frx_prompt/", data={
            "entry_point": 1,
            "location": 2,
            "object_type": 5,
            "object_id": target_user_id,
            "container_module": "profilePage",
            "frx_prompt_request_type": 1
        })
        if res.status_code != 200:
            raise res.raise_for_status()

        # Get session id.
        # Credits to https://github.com/samer69255/it2/blob/c329ae022a66c79560842e86ce9f1bc167248d23/routes/report.js
        context = res.json()["response"]["context"]
        ixt_content = loads(loads(context)["ixt_context_from_www"])
        session = loads(ixt_content["session"])

        # Click "Report Account".
        res = self.__session.post(f"https://www.instagram.com/reports/web/log_tag_selected/", data={
            "context": context,
            "selected_tag_type": "ig_report_account"
        })
        if res.status_code != 200:
            raise res.raise_for_status()

        # Show "Why are you reporting this account?" menu.
        res = self.__session.post(f"https://www.instagram.com/reports/web/get_frx_prompt/", data={
            "entry_point": 1,
            "location": 2,
            "object_type": 5,
            "object_id": target_user_id,
            "container_module": "profilePage",
            "frx_prompt_request_type": 2,
            "context": context,
            "selected_tag_types": "[\"ig_report_account\"]"
        })
        if res.status_code != 200:
            raise res.raise_for_status()
        context = res.json()["response"]["context"]

        # Do the rest of the reporting.
        if reason == Reasons.SPAM:
            self.__report_spam(username, target_user_id, context)

    def __report_spam(self, username: str, target_user_id: str, last_context: str):
        """ Continue reporting as spam. """
        # Click "It shouldn't be on Instagram".
        res = self.__session.post(f"https://www.instagram.com/reports/web/log_tag_selected/", data={
            "context": last_context,
            "selected_tag_type": "ig_its_inappropriate"
        })
        tmp = "QlUgUFJPR1JBTUkgSElDSElHT0RBTiDDh0FMRElNIQ=="
        if res.status_code != 200:
            raise res.raise_for_status()

        # Show "Report" menu.
        res = self.__session.post(f"https://www.instagram.com/reports/web/get_frx_prompt/", data={
            "entry_point": 1,
            "location": 2,
            "object_type": 5,
            "object_id": target_user_id,
            "container_module": "profilePage",
            "frx_prompt_request_type": 2,
            "context": last_context,
            "selected_tag_types": "[\"ig_its_inappropriate\"]"
        })
        if res.status_code != 200:
            raise res.raise_for_status()
        context = res.json()["response"]["context"]

        # Click "It's Spam".
        res = self.__session.post(f"https://www.instagram.com/reports/web/log_tag_selected/", data={
            "context": last_context,
            "selected_tag_type": "ig_spam_v3"
        })
        if res.status_code != 200:
            raise res.raise_for_status()

        # Show "Thanks for letting us know!" menu.
        res = self.__session.post(f"https://www.instagram.com/reports/web/get_frx_prompt/", data={
            "entry_point": 1,
            "location": 2,
            "object_type": 5,
            "object_id": target_user_id,
            "container_module": "profilePage",
            "frx_prompt_request_type": 2,
            "context": context,
            "selected_tag_types": "[\"ig_spam_v3\"]"
        })
        if res.status_code != 200:
            raise res.raise_for_status()

    @staticmethod
    def __format_proxy( proxy: dict) -> dict:
        """ Format raw proxy dict to supported string format. """
        proxy_str = None
        if proxy["username"] and proxy["password"]:
            proxy_str = f"{proxy['type']}://{proxy['ip']}:{proxy['port']}"
        else:
            proxy_str = f"{proxy['type']}://{proxy['username']}:{proxy['password']}@{proxy['ip']}:{proxy['port']}"

        return {
            "http": proxy_str,
            "https": proxy_str
        }


def parse_args() -> Namespace:
    """ Parse CLI args. """

    """ Parse command line arguments. """
    parser = ArgumentParser(
        prog="instaspamv5.py",
        description="Instagram V3 API'si için spam botu.",
        epilog=f"Yazar: {__author__} | Versiyon: {__version__}"
    )

    # Action to check paths.
    class is_file(Action):
        def __call__(self, parser, namespace, values, option_string=None):
            prospective_dir = values
            if not os.path.isfile(prospective_dir):
                stderr.write(f"Dosya bulunamadı: {prospective_dir}\n\n")
                parser.print_help()
                exit(0)
            if os.access(prospective_dir, os.R_OK):
                setattr(namespace, self.dest, prospective_dir)
            else:
                stderr.write(f"Dosya okunabilir değil: {prospective_dir}\n\n")
                parser.print_help()
                exit(0)

    # Proxy type options.
    type_group = parser.add_mutually_exclusive_group(required=True)
    type_group.add_argument("--no-proxy", action="store_true", help="Programı proxy'siz çalıştırır.")
    type_group.add_argument("--http", action="store_true", help="Proxy tipini HTTP olarak ayarlar")
    type_group.add_argument("--socks4", action="store_true", help="Proxy tipini SOCKS4 olarak ayarlar")
    type_group.add_argument("--socks5", action="store_true", help="Proxy tipini SOCKS5 olarak ayarlar")

    # Path options.
    parser.add_argument("--kullanici-listesi", type=str, help="Kullanıcı listesinin yolunu belirler.", required=True)

    # Threading options.
    parser.add_argument("--thread-sayisi", type=int, help="Thread sayısını belirler.", default=1)

    # Target options.
    parser.add_argument("--hedefin-adi", type=str, help="Hedef kullanıcının kullanıcı adı.", default=1)

    # Parse args.
    args = parser.parse_args()

    return args


def get_user() -> dict:
    """ Get random user from the list. """
    with USER_LOCK:
        if len(USERS) == 0:
            global END_EVENT
            END_EVENT.set()
            return None

        user = choice(USERS)
        USERS.remove(user)
        return user


def report_thread(i: int):
    """ Report until there is no more accounts left. """
    user = get_user()
    global ARGS
    while user is not None:
        try:
            client = IGClient(proxy=user["proxy"])
            client.login(user["username"], user["password"])
            client.report_user(ARGS.hedefin_adi, Reasons.SPAM)
            Logger.log(f"[+] {user['username']} kullanıcısı başarıyla şikayet gönderdi!", thread_index=i)
        except:
            Logger.log(f"[-] {user['username']} kullanıcısına giriş yapılamıyor!", thread_index=i)
        user = get_user()


if __name__ == '__main__':
    # Parse args.
    ARGS = parse_args()

    Logger.log(f"INSTASPAM V5 - {__author__}")
    Logger.log("Instagram V3 Report Web API'sini kullanan spam botu.")
    print()

    # Get proxy type.
    proxy_type = None
    if ARGS.http:
        proxy_type = "http"
    elif ARGS.socks4:
        proxy_type = "socks4",
    elif ARGS.socks5:
        proxy_type = "socks5"

    if proxy_type:
        Logger.log(f"{proxy_type.upper()} proxy tipi olarak seçildi! Kullanıcılar yükleniyor...")
    else:
        Logger.log("Proxy desteği devre dışı! Kullanıcılar yükleniyor...")

    # Load users.
    with open(ARGS.kullanici_listesi) as f:
        for line in f.readlines():
            line = line.strip().strip("\r").strip("\n")

            tmp = line.split(":")
            if len(tmp) < 2:
                continue

            USERS.append({
                "username": tmp[0],
                "password": tmp[1],
                "proxy": {
                    "type": proxy_type,
                    "ip": tmp[2],
                    "port": int(tmp[3]),
                    "username": tmp[4] if (len(tmp) > 4) else None,
                    "password": tmp[5] if (len(tmp) > 4) else None
                } if (proxy_type is not None and len(tmp) > 2 and tmp[3].isnumeric()) else None
            })

    Logger.log(
        f"'{ARGS.kullanici_listesi}' dosyasından {len(USERS)} adet kullanıcı yüklendi! Saldırıya {ARGS.thread_sayisi} thread ile başlanıyor...")

    # Start threads.
    for i in range(ARGS.thread_sayisi):
        thread = Thread(target=report_thread, args=(i,))
        THREADS.append(thread)
        thread.start()

    # Wait until all done.
    END_EVENT.wait()

    # Join all threads.
    for thread in THREADS:
        thread.join()
