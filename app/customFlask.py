from flask import Flask


class CustomFlask(Flask):
    def process_response(self, response):
        response = super().process_response(response)
        response.headers['Server'] = ''
        return response
