# -*- coding: utf-8 -*-

from django.db import models, migrations
from django.conf import settings

import helpdesk.models

class Migration(migrations.Migration):
    dependencies = [
        ("helpdesk", "0040_alter_kbitem_remove_order_check")
    ]

    operations = [
        migrations.CreateModel(
            name="doltdesk_agents",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        verbose_name="ID",
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "name",
                    models.CharField(unique=True, null=False, blank=False, verbose_name="Agent Name", max_length=64),
                ),
                (
                    "password",
                    models.CharField(unique=True, null=False, blank=False, verbose_name="Agent Password", max_length=512),
                ),
                (
                    "branch_prefix",
                    models.CharField(unique=True, null=False, blank=False, verbose_name="Branch Prefix", max_length=64),
                ),
                (
                    "db_user",
                    models.CharField(unique=True, null=False, blank=False, verbose_name="Agent DB Username", max_length=32),
                ),
                (
                    "db_pass",
                    models.CharField(unique=True, null=False, blank=False, verbose_name="", max_length=32),
                ),
            ],
            options={
                "verbose_name_plural": "Doltdesk Agents",
                "verbose_name": "Doltdesk Agent",
                "ordering": ["name"],
            }
        )
    ]
