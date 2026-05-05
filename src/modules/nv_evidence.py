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
import PIL
from PIL import Image

def main():
    parser = argparse.ArgumentParser(description="Takes screenshot via wetty for evidence.")
    parser.add_argument('--path', type=str, help="Input directory path")
    parser.add_argument('--url', type=str, default="http://localhost:3000/wetty", help="Wetty url (Default: http://localhost:3000/wetty)")

    args = parser.parse_args()
    argcomplete.autocomplete(parser)

    global driver
    options = Options()
    service = Service("/usr/local/bin/geckodriver")
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=800,600")
    # options.set_preference("permissions.default.image", 2)
    driver = webdriver.Firefox(options=options, service=service)
    driver.get(args.url)
    driver.implicitly_wait(2)
    input_field = driver.find_element(By.CLASS_NAME, "xterm-helper-textarea")
    input_field.send_keys("whoami")
    input_field.send_keys(Keys.ENTER)
    time.sleep(1)

    png = driver.get_screenshot_as_png()
    full_img = Image.open(BytesIO(png))
    x, y = full_img.size
    full_img.crop((0, 0, x-100, y)).save(os.curdir + "/s.png")
    full_img.save(os.curdir + "/full_s.png")

    driver.quit()