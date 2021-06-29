import re
from subprocess import run, PIPE
 
 
def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])
 
 
def main():
    ipaddress = '127.0.0.1'
    oid = '.1.3.6.1.2.1.25.6.3.1'
    community = 'public'
    port = '161'
    host = '{}:{}'.format(ipaddress, port)
    timeout = 1000
 
    cmdargs = [
        'snmpwalk', '-Pe', '-t', str(timeout), '-r', '0', '-v', '2c',
        '-c', community, host, oid
    ]
    print(cmdargs)
    cmd = run(cmdargs, stdout=PIPE, stderr=PIPE)
 
    if cmd.returncode != 0:
        print(cmd.stderr, host)
    else:
        cmdoutput = cmd.stdout.splitlines()
        result = []
        for line in cmdoutput:
            item = line.decode('utf-8').split(' = ', 1)
            if len(item) > 1:
                if 'No Such Instance' in item[1]:
                    item[1] = None
                result.append(tuple(item))
            else:
                prev_item = list(result[-1])
                prev_item[1] += '\n' + item[0]
                result[-1] = tuple(prev_item)
        for row in result:
            print(row)
            split = row[1].split(':', 2);
            if split[0] == 'Hex-STRING':
                temp = split[1].replace('\n', '')
                temp = temp.replace(' ', '')
                hex = re.sub('/[^a-zA-Z0-9]+/', '', temp)
                print(hex)
                bstr = "{0:08b}".format(int(hex, 16))
                print(bitstring_to_bytes(bstr).decode('gbk'))
 
 
if __name__ == '__main__':
    main()
