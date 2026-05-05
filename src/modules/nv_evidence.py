import argparse, argcomplete
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
    # wait = WebDriverWait(driver, 10)
    # input_field = wait.until(EC.element_to_be_clickable((By.CLASS_NAME, "xterm-helper-textarea")))
    # input_field.click()
    # input_field = driver.find_element(By.CLASS_NAME, "xterm-helper-textarea")
    # input_field.send_keys("whoami")
    # input_field.send_keys(Keys.ENTER)
    time.sleep(1)

    driver.save_screenshot(os.curdir + "/s.png")

    driver.quit()