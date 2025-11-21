import requests
import argparse
import time
from bs4 import BeautifulSoup
import json
import getpass
from des import str_enc


# 获取drcom信息（包括IP和登录状态）
def get_drcom_info():
    try:
        url = "http://172.20.30.1/drcom/chkstatus?callback="
        response = requests.get(url, timeout=5)
        content = response.text.strip()
        # 去除外层的括号
        if content.startswith("(") and content.endswith(")"):
            content = content[1:-1]

        data = json.loads(content)
        return data
    except Exception as e:
        print(f"Error getting drcom info: {e}")
        return None


# 通过des.py的加密函数加密


def strEnc(data, firstKey, secondKey, thirdKey):
    return str_enc(data, firstKey, secondKey, thirdKey)


# # 调用Node.js执行des.js里的加密函数
# def strEnc(data, firstKey, secondKey, thirdKey):
#     result = subprocess.run(
#         ['node', 'des.js', data, firstKey, secondKey, thirdKey],
#         capture_output=True, text=True
#     )

#     # 检查命令执行结果
#     if result.returncode == 0:
#         print("Encryption result: ", result.stdout.strip())
#     else:
#         raise Exception("An error occurred during execution: ", result.stderr)

#     return result.stdout.strip()

# 用于格式化输出online_list


def format_online_list_print(data_list):
    print("online_list:")
    # 获取字段名列表，假设所有字典有相同的字段
    headers = list(data_list[0].keys())

    # 打印表头，每个字段宽度设置为10
    header_row = "|".join(f"{header:<10}" for header in headers)
    print("-" * len(header_row))  # 打印分隔线
    print(header_row)
    print("-" * len(header_row))  # 打印分隔线

    # 打印每行数据
    for item in data_list:
        formatted_line = "|".join(f"{str(item[key]):<10}" for key in headers)
        print(formatted_line)
    print("-" * len(header_row))  # 打印分隔线


def extract_value_by_id_or_name(soup, attribute_type, attribute_value):
    """
    Extracts the value of an HTML element identified by its ID or name attribute.

    Parameters:
    - soup: BeautifulSoup object representing the HTML document.
    - attribute_type: A string specifying the type of attribute to search for ('id' or 'name').
    - attribute_value: The value of the 'id' or 'name' attribute to search for.

    Returns:
    - The value of the 'value' attribute of the found element, or None if the element is not found.
    """
    if attribute_type not in ["id", "name"]:
        raise ValueError(
            f"Attribute type must be 'id' or 'name', but got: {attribute_type}!"
        )

    if attribute_type == "id":
        element = soup.find(id=attribute_value)
    else:  # attribute_type == 'name'
        element = soup.find(attrs={"name": attribute_value})

    if element:
        return element.get("value")
    else:
        raise Exception(f"Element with {attribute_type} = {attribute_value} not found!")


# 实际登录函数


def do_login(username, password, ip):
    
    # 初始URL，可能是你想访问的网站的URL，这个网站将你重定向到SSO登录页面
    initial_url = f"http://172.20.30.2:8080/Self/sso_login?login_method=1&wlan_user_ip={ip}&wlan_user_ipv6=&wlan_user_mac=000000000000&wlan_ac_ip=172.20.30.254&wlan_ac_name=&mac_type=1&authex_enable=&type=1"

    print(f"Initial login URL: {initial_url}")

    # 创建一个session对象，这样Cookies和会话信息就可以在请求之间保持了
    session = requests.Session()

    # 首先访问初始URL
    response = session.get(initial_url)

    # 使用BeautifulSoup解析HTML
    soup = BeautifulSoup(response.text, "lxml")

    # 查找id为"lt"的元素
    lt_value = extract_value_by_id_or_name(soup, "id", "lt")
    print("lt:", lt_value)

    # 查找name为"execution"的元素
    execution_value = extract_value_by_id_or_name(soup, "name", "execution")
    print("execution:", execution_value)

    # 查找name为"_eventId"的元素
    event_id_value = extract_value_by_id_or_name(soup, "name", "_eventId")
    print("_eventId:", event_id_value)

    # 检查是否被重定向到SSO登录页
    if response.history:
        # SSO登录表单的URL，这通常是在你被重定向到SSO登录页面时的URL
        # sso_login_url = "https://sso.dlut.edu.cn/cas/login?service=https%3A%2F%2Fportal.dlut.edu.cn%2Ftp%2F"
        sso_login_url = response.url
        print(f"跳转到sso登录页面: {sso_login_url}")

        # 准备登录数据，这个需要根据SSO页面的具体要求来填写
        # 在实际情况中，可能需要额外的字段，比如CSRF令牌等
        login_data = {
            "rsa": strEnc(username + password + lt_value, "1", "2", "3"),
            "ul": len(username),
            "pl": len(password),
            "sl": 0,
            "lt": lt_value,
            "execution": execution_value,
            "_eventId": event_id_value,
        }
        print(f"Login form: \n{login_data}")

        # 提交登录表单
        login_response = session.post(sso_login_url, data=login_data)

        # 检查登录是否成功，由于登录成功后会重定向到校园网首页，失败则还是在sso_login_url，通过检查重定向历史记录来判断
        if login_response.history:
            print("Redirection...")

            time.sleep(2)  # 等待2秒，防止后台新登录的数据还未刷新
            # 访问设备在线列表，并打印
            online_list_url = f"http://172.20.30.2:8080/Self/dashboard/getOnlineList"
            online_list_response = session.get(online_list_url)
            online_list = json.loads(online_list_response.text)
            format_online_list_print(online_list)
        else:
            print(
                "Login failed, no redirection found. Please check the entered account, password, and IP."
            )
            return False
    else:
        raise Exception("No redirection, direct access!")
    return True


# 处理每次登录


def login(username, password, ip):

    if not username:
        username = input("Please enter your username: ")

    if not password:
        password = getpass.getpass("Please enter your password: ")

    # 打印参数
    print(
        f"Current login information: Username: {username}, Password: ******, IP: {ip}"
    )

    max_attempts = 3
    attempt_count = 1

    while attempt_count < max_attempts:
        try:
            # 尝试登录
            print(f"Attempting to log in for the {attempt_count}th time...")
            if do_login(username, password, ip):
                break
            else:
                return f"ip: {ip}, Login failed!"

        except Exception as e:
            # 如果操作失败，打印错误消息（或进行其他错误处理）
            print(f"Login failed: {e}, retrying...")
            attempt_count += 1
            time.sleep(3)  # 等待3秒

    if attempt_count == max_attempts:
        return f"ip: {ip}, Reached the maximum number of login attempts, login failed!"
    else:
        return (
            f"ip: {ip}, Please confirm if have successfully connected to the network."
        )


def main():
    # 创建 ArgumentParser 对象
    parser = argparse.ArgumentParser(description="Processing required parameters")

    # 添加参数
    parser.add_argument("-u", "--username", type=str, help="The username")
    parser.add_argument("-p", "--password", type=str, help="The password")
    parser.add_argument("-i", "--ip", type=str, help="The IP address")

    # 解析命令行参数
    args = parser.parse_args()

    info = get_drcom_info()

    if info and info.get("result") == 1:
        print("Current status: Online. No need to login.")
        return

    if args.ip:
        print(login(args.username, args.password, args.ip))
    else:
        ip = info.get("v46ip") if info else None
        if ip:
            print(f"Detected IP: {ip}")
            ip_list = [ip]
        else:
            raise Exception("Failed to get local IP address!")

        result = []
        for ip in ip_list:
            result.append(login(args.username, args.password, ip))
        for r in result:
            print(r)


if __name__ == "__main__":
    main()
