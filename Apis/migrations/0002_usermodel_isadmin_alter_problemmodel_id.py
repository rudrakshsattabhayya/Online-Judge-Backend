# Generated by Django 4.2.1 on 2023-05-12 16:22

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('Apis', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='usermodel',
            name='isAdmin',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='problemmodel',
            name='id',
            field=models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False),
        ),
    ]
