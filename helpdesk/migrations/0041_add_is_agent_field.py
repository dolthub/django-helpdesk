# Generated manually for Django-Helpdesk

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('helpdesk', '0040_alter_kbitem_remove_order_check'),
    ]

    operations = [
        migrations.AddField(
            model_name='usersettings',
            name='is_agent',
            field=models.BooleanField(
                default=False,
                help_text='Designates whether this user is an agent who can handle tickets. Agents have special permissions and responsibilities in the helpdesk system.',
                verbose_name='Is Agent?'
            ),
        ),
    ]