class Udp_check():
    def __init__(self, IP_content):
        self.IP_content = IP_content
        self.IP_header_len = 20  # IP头部20字节
        self.check_content = []  # UDP校验和部分
        # UDP校验和部分 = UDP伪首部 + UDP内容（UDP首部 + UDP数据部分）

    def add_udp_pseudo_header_content(self):
        # UDP伪首部 = 源IP地址 + 目的IP地址 + 0x00 +协议字段 + UDP长度

        # IP源地址为IP报文的13、14、15、16字节，即伪首部的源IP地址字段
        self.check_content.append(self.IP_content[12])
        self.check_content.append(self.IP_content[13])
        self.check_content.append(self.IP_content[14])
        self.check_content.append(self.IP_content[15])

        # IP目的地址为IP报文的17、18、19、20字节，即伪首部的目的IP地址字段
        self.check_content.append(self.IP_content[16])
        self.check_content.append(self.IP_content[17])
        self.check_content.append(self.IP_content[18])
        self.check_content.append(self.IP_content[19])

        # UDP伪首部的第三个字段，为0x00
        self.check_content.append(0x00)

        # 协议类型是IP报文的第10字节，即伪首部的协议类型字段
        self.check_content.append(self.IP_content[9])

        # UDP数据长度是UDP报文中的第5、6字节，伪首部的长度字段

        self.check_content.append(self.IP_content[self.IP_header_len + 4])
        self.check_content.append(self.IP_content[self.IP_header_len + 5])

    def add_udp_content(self):
        # udp内容的长度
        udp_content_len = len(self.IP_content) - self.IP_header_len
        # 往校验部分添加udp内容
        for i in range(udp_content_len):
            self.check_content.append(self.IP_content[self.IP_header_len + i])

    def set_and_fill_zero(self):
        self.check_content[18] = 0  # 把原来的校验和设置为0
        self.check_content[19] = 0

        if len(self.check_content) % 2 == 1:  # 整个报文长度为奇数需要补充0
            self.check_content.append(0x00)

    def check_process(self):
        data_sum = []

        # 先需要将前后二个数合并成16位长度的16进制的数
        for num in range(0, len(self.check_content), 2):
            # 如果转换为16进制后只有1位需要高位补0操作，用zfill方法
            part1 = str(hex(self.check_content[num]))[2:].zfill(2)
            part2 = str(hex(self.check_content[num + 1]))[2:].zfill(2)
            part_all = part1 + part2
            data_sum.append(int(part_all, 16))
        ##        print(data_sum)

        sum_total = sum(data_sum)  # 计算所有数的和
        sum_total_hex = str(hex(sum_total))[2:]  # 16进制化
        sum_total_hex_len = len(sum_total_hex)  # 取得字节长度

        if sum_total_hex_len > 4:  # 求和的结果大于2个[字节16位]的话，分割成2个2字节16位数
            part1 = int(sum_total_hex[: sum_total_hex_len - 4], 16)  # 分割第一、二字节的十六进制数字，转换为10进制
            part2 = int(sum_total_hex[sum_total_hex_len - 4:], 16)  # 分割第三、四字节的十六进制数字，转换为10进制
            part_all = part1 + part2
        else:
            part_all = sum_total

        last_check_sum = str(hex(65535 - part_all))[2:]  # 二个字节的十六进制数之和取反
        return sum_total_hex, last_check_sum

    def run(self):
        self.add_udp_pseudo_header_content()
        self.add_udp_content()
        check1 = str(hex(self.check_content[18]))[2:]
        check2 = str(hex(self.check_content[19]))[2:]

        print("检验和：0x{0}{1}".format(check1, check2))

        self.set_and_fill_zero()
        print('需要计算的UDP校验和内容为：{}'.format((self.check_content)))
        ## UDP校验和部分准备完成

        sum_total_hex, last_check_sum = self.check_process()
        print("sum_total_hex: 0x{}".format(sum_total_hex))
        print("检验和：0x{0}".format(last_check_sum))

        temp = hex((int(sum_total_hex, 16) >> 16) + (int(sum_total_hex, 16) & 0xffff))
        print("(0x{0} >> 16) + (0x{0} & 0xffff) = {1} ".format(sum_total_hex, temp))

        temp2 = hex(int(temp, 16) + int('0x' + check1 + check2, 16))
        print("{0} + 0x{1}{2} = {3}".format(temp, check1, check2, temp2))


if __name__ == '__main__':
    IP_content_hex = ['45', '00', '01', '23', '7f', '1e', '00', '00', '40', '11', 'd5', '85', '0a', '08', '88', '17',
                      '0a', '08', '88', 'ff', 'd6', '83', 'd6', '83', '01', '0f', '5f', '62', '00', '73', '68', '79',
                      '79', '79', '66', '2d', '67', '75', '74', '69', '6e', '67', '74', '00', '00', '00', '00', '00',
                      '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '20', '5f', '27', '02',
                      '00', '00', '00', '00', '30', 'b4', '9f', '06', '00', '00', '00', '00', '33', '27', '00', '00',
                      '00', '00', '00', '00', '10', '5f', '27', '02', '00', '00', '00', '00', 'c0', '04', '6e', '05',
                      '00', '00', '00', '00', '7c', '6a', '7a', '70', '00', '00', '00', '00', '98', 'a3', 'da', '6f',
                      '00', '00', '00', '00', '59', 'b8', '9f', '06', '00', '00', '00', '00', '00', '00', '00', '00',
                      '00', '00', '00', '00', '70', '97', 'da', '04', '00', '00', '00', '00', 'a4', 'b4', '9f', '06',
                      '00', '00', '00', '00', 'c0', 'b4', '9f', '06', '00', '00', '00', '00', 'a8', 'd9', '7a', '7b',
                      '61', '63', '36', '35', '64', '66', '64', '62', '2d', '36', '32', '37', '34', '2d', '34', '65',
                      '65', '34', '2d', '62', '63', '64', '64', '2d', '34', '35', '62', '36', '61', '62', '63', '63',
                      '37', '31', '36', '39', '7d', '00', '00', '00', '00', '00', '00', '00', '01', '00', '00', '00',
                      '00', '00', '00', '00', 'a0', 'b4', '9f', '06', '00', '00', '00', '00', '00', '00', '00', '00',
                      '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00',
                      '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00',
                      '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00',
                      '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '35',
                      'a5', '8a', 'f3']
    print("IP_content：{}".format(len(IP_content_hex)))

    IP_content_dec = [int(i, 16) for i in IP_content_hex]  # 十进制化
    udp_check = Udp_check(IP_content_dec)
    udp_check.run()
