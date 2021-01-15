Żeby uruchomić projekt należy użyć komendy:
`docker-compose up -d`
a następnie:
`docker-compose exec web flask reset-db`
Nie byłem w stanie sprawić, żeby dało się wywołać obie komendy w jednym skrypcie, natomiast wywołanie
`flask reset-db` jako ENTRYPOINT w Dockerfile powoduje zakończenie działania kontenera web.