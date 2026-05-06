import argparse, argcomplete
from io import BytesIO
import os
import time
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from PIL import Image
from pathlib import Path

from src.solvers.apache import APACHE_FILENAME_FOR_ALL

def send_command(input_field, command, delay=0.5):
    input_field.send_keys(command)
    input_field.send_keys(Keys.ENTER)
    time.sleep(delay)

def save_screenshot(driver, filename):
    png = driver.get_screenshot_as_png()
    full_img = Image.open(BytesIO(png))
    x, y = full_img.size
    full_img.crop((0, 0, x-100, y)).save(os.curdir + "/" + filename)

def main():
    parser = argparse.ArgumentParser(description="Takes screenshot via wetty for evidence.")
    parser.add_argument('--path', type=str, help="Input directory path")
    parser.add_argument('--url', type=str, default="http://localhost:3000/wetty", help="Wetty url (Default: http://localhost:3000/wetty)")

    args = parser.parse_args()
    argcomplete.autocomplete(parser)

    options = Options()
    service = Service("/usr/local/bin/geckodriver")
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=800,600")
    # options.set_preference("permissions.default.image", 2)
    driver = webdriver.Firefox(options=options, service=service)
    driver.get(args.url)
    wait = WebDriverWait(driver, timeout=30, poll_frequency=1)
    input_field = wait.until(EC.presence_of_element_located((By.CLASS_NAME, "xterm-helper-textarea")))
    send_command(input_field, "cd " + args.path, delay=0.5)
    send_command(input_field, "clear", delay=0.5)

    directory = Path(args.path)
    if (directory / APACHE_FILENAME_FOR_ALL).is_file():
        input_field.send_keys("head -30 " + APACHE_FILENAME_FOR_ALL)
        input_field.send_keys(Keys.ENTER)
        time.sleep(0.5)
        save_screenshot(driver, "apache.png")

    driver.quit()