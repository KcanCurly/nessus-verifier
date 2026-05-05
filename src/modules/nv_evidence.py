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
    # Find all elements on the current page (or within the current iframe)
    all_elements = driver.find_elements(By.XPATH, "//*")

    print(f"{'TAG':<15} | {'ID':<20} | {'CLASSES'}")
    print("-" * 60)

    for element in all_elements:
        try:
            tag = element.tag_name
            id_attr = element.get_attribute("id") or "N/A"
            class_attr = element.get_attribute("class") or "N/A"
            
            # Only print if it's a visible or interactive-style element to save space
            # Or remove this 'if' to see absolutely everything
            if tag in ["div", "textarea", "iframe", "canvas", "span", "input"]:
                print(f"{tag:<15} | {id_attr:<20} | {class_attr}")
        except:
            # Elements can become "stale" if the page refreshes while iterating
            continue

    driver.quit()