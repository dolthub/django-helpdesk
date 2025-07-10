#!/usr/bin/python
"""
django-helpdesk - A Django powered ticket tracker for small enterprise.

(c) Copyright 2008 Jutda. All Rights Reserved. See LICENSE for details.

scripts/dolt_commit.py - Commit everything on main
"""

from django.core.management.base import BaseCommand

class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument(
            "-m",
            "--message",
            nargs="*",
            help="dolt commit message",
        )

    def handle(self, *args, **options):
        message = options["message"]

        from django.db import connection

        try:
            with connection.cursor() as cursor:
                sql = 'CALL dolt_commit(%s, %s);'
                cursor.execute(sql, ['-Am', message])
        except Exception as e:
            self.stdout.write('failed to execute dolt_commit')
            raise e
