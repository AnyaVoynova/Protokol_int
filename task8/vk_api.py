import argparse
import requests

API_VERSION = "5.131"


class VKApi:
    def __init__(self, access_token):
        self.access_token = access_token

    def get_friends(self, user_id):
        # Формирование параметров запроса
        params = {
            'user_id': user_id,
            'fields': 'first_name,last_name',
            'access_token': self.access_token,
            'v': API_VERSION
        }
        # Отправка запроса к API ВКонтакте и получение ответа в формате JSON
        response = requests.get("https://api.vk.com/method/friends.get", params=params).json()
        # Извлечение списка друзей из ответа
        friends = response.get('response', {}).get('items', [])
        return friends

    def print_friends(self, friends):
        # Вывод списка друзей в удобочитаемом виде
        for idx, friend in enumerate(friends, start=1):
            print(f"{idx}. {friend['first_name']} {friend['last_name']}")


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--access_token", help="VK API access token")
    parser.add_argument("--user_id", help="VK user ID")
    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()

    if not args.access_token:
        args.access_token = input("Enter VK API access token: ")

    if not args.user_id:
        args.user_id = input("Enter VK user ID: ")

    try:
        api = VKApi(args.access_token)

        friends = api.get_friends(args.user_id)
        api.print_friends(friends)

    except KeyboardInterrupt:
        exit()