# Generated by Django 4.2.1 on 2023-06-09 05:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Apis', '0007_remove_submissionmodel_testcases'),
    ]

    operations = [
        migrations.AddField(
            model_name='usermodel',
            name='hashedPassword',
            field=models.CharField(max_length=500, null=True),
        ),
    ]
