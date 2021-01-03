#!/usr/bin/env python3

import sys
import paho.mqtt.client as mqtt
import json
from time import localtime, strftime
from datetime import datetime, timedelta
import time
import signal, os
import configparser
import smtplib
from email.message import EmailMessage
import logging

nodes = {"start": datetime.now()}

def signal_handler(signum, frame):
    logging.info('Signal handler called with signal ' + str(signum))
    if signum == signal.SIGINT.value:
        client.unsubscribe(mqtt_topic)
        client.disconnect()
        client.loop_stop()
        logging.info("[mqtt] Connection disconnect")
        exit()
    elif signum == signal.SIGUSR1.value:
        logging.info("Print nodes table:")
        copy_of_nodes = nodes.copy()
        for node, timestamp in copy_of_nodes.items():
            logging.info("node: '" + node + "' timestamp: " + timestamp.strftime("%Y-%m-%d %H:%M:%S"))
    else:
        logging.warn("No signal handler defined")

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logging.info("[mqtt] Connection successful")
    elif rc == 1:
        logging.error("[mqtt] Connection refused - incorrect protocol version")
    elif rc == 2:
        logging.error("[mqtt] Connection refused - invalid client identifier")
    elif rc == 3:
        logging.error("[mqtt] Connection refused - server unavailable")
    elif rc == 4:
        logging.error("[mqtt] Connection refused - bad username or password")
    elif rc == 5:
        logging.error("[mqtt] Connection refused - not authorised")
    else:
        logging.error("[mqtt] Unknown return code: " + str(rc))

    rc = client.subscribe(mqtt_topic, 0)

    if rc[0] == 0:
        logging.info("[mqtt] Subscribtion successful - message id: " + str(rc[1]))
    elif rc[0] == 1:
        logging.error("[mqtt] Subscribtion error - client not connected")
    else:
        logging.error("[mqtt] Unknown return code: " + str(rc))

def on_message(client, userdata, msg):
    data = json.loads(msg.payload.decode('utf-8'))
    dev = { data["dev_id"]: datetime.now() }
    nodes.update(dev)

def on_disconnect(client, userdata, rc):
    logging.info("Disconnect with result code "+str(rc))

def on_log(mqtt, obj, level, string):
    logging.debug(string)

try:
    config_file = str(sys.argv[1])
except IndexError:
    print('missing argument')
except ValueError:
    print('argument must be a string')
else:
    try:
        config = configparser.ConfigParser()
        config.read(config_file)

        app_id = config['DEFAULT']['App_ID']
        timeout = int(config['DEFAULT']['Timeout'])
        logfile = config['DEFAULT']['Logfile']

        mqtt_topic = app_id + "/devices/+/up"
        mqtt_username = config['MQTT']['MQTT_Username']
        mqtt_password = config['MQTT']['MQTT_Password']
        mqtt_server = config['MQTT']['MQTT_Server']
        mqtt_port = int(config['MQTT']['MQTT_Port'])
        mqtt_cert = config['MQTT']['MQTT_Cert']

        mail_sender = config['MAIL']['Mail_Sender']
        mail_receiver = config['MAIL']['Mail_Receiver']
        mail_username = config['MAIL']['Mail_Username']
        mail_password = config['MAIL']['Mail_Password']
        mail_server = config['MAIL']['Mail_Server']
        mail_port = int(config['MAIL']['Mail_Port'])
    except :
        print("error open config file")
        sys.exit()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGUSR1, signal_handler)

    logging.basicConfig(filename=logfile, format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
    logging.info("Starting")

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    client.on_log = on_log

    client.tls_set(ca_certs=mqtt_cert)
    client.username_pw_set(username=mqtt_username, password=mqtt_password)

    try:
        client.connect(mqtt_server, mqtt_port, 30)
    except:
        logging.error("[mqtt] Error connect")
        exit()

    client.loop_start()

    while True:
        copy_of_nodes = nodes.copy()
        for node, timestamp in copy_of_nodes.items():
            if (datetime.now() - timedelta(minutes=timeout)) > timestamp:
                mail_msg = EmailMessage()
                mail_msg['From'] = mail_sender
                mail_msg['To'] = mail_receiver
                mail_msg['Subject'] = app_id + " node down"
                mail_msg.set_content("last msg from node '" + node + "'  was on " + timestamp.strftime("%d %b %H:%M:%S"))

                mail_client = smtplib.SMTP(mail_server, mail_port)
                mail_client.starttls()
                mail_client.login(mail_username, mail_password)
                mail_client.sendmail(mail_sender, mail_receiver, mail_msg.as_string())
                mail_client.quit()

                logging.warn("remove " + node + " from dict")
                del nodes[node]
        time.sleep(60)
