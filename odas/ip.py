import ipinfo
import os

token = os.environ.get('IPINFO_TOKEN')
flask_env = os.environ.get('flask_env')

handler = ipinfo.getHandler(token)


def get_location_from_ip(ip):
    if flask_env == 'development':  # to żeby nie przekroczyć darmowej liczby żądań na ipinfo
        return 'localhost'
    else:
        res = handler.getDetails(ip)
        try:
            return res.details['city'] + ', ' + res.details['country']
        except KeyError:
            return 'niezidentyfikowana'
