from celery import Celery
from src.email import mail, create_message
from asgiref.sync import async_to_sync

c_app = Celery()

c_app.config_from_object("src.config")


@c_app.task()
def task_email_send(recipients: list[str], subject: str, body: str):
    message = create_message(
        recipients=recipients,
        subject=subject,
        body=body,
    )
    async_to_sync(mail.send_message)(message)
    print('Email sent!')
