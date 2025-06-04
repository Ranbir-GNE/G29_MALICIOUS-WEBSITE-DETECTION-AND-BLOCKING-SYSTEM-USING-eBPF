#!/usr/bin/python3 -u
import sys
import json
import socket

n_new = 0
n_update = 0
n_complete = 0
n_active = 0
n_purge = 0
n_orphan = 0
n_dup = 0

CLRSCR = '\x1b[2J'
CLREOL = '\x1b[K'

RED = '\x1b[31m'
GREEN = '\x1b[32m'
YELLOW = '\x1b[33m'
BLUE = '\x1b[34m'
MAGENTA = '\x1b[35m'
CYAN = '\x1b[36m'
WHITE = '\x1b[37m'
RESET = '\x1b[0m'

flow_set = set()

if len(sys.argv) < 3:
    print('params?')
    sys.exit(1)

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((sys.argv[1], int(sys.argv[2])))
    F = s.makefile()
except:
    print('connection?')
    sys.exit(1)

def print_flow(flow, info):
    print(f"{flow['digest_prev'][-1][:10]} " \
        f"{flow['digest'][:10]}:{flow['digest_prev'][0][:10]}: {info}{CLREOL}")

def update_flow(flow, prefix):
    global n_orphan

    if flow['digest'] in flow_set:
        return True

    found = False
    for digest_prev in flow['digest_prev']:
        if digest_prev in flow_set:
            found = True
            flow_set.remove(digest_prev)
            print(f"{flow['digest_prev'][-1][:10]} " \
                f"{digest_prev[:10]}: {YELLOW}removed{RESET}{CLREOL}")

    if found:
        flow_add(flow)
        print_flow(flow, f'{prefix}: digest updated')
    else:
        n_orphan += 1
        print_flow(flow, f'{RED}{prefix}: orphaned{RESET}')

    return found

def flow_add(flow):
    flow_set.add(flow['digest'])
    print(f"{flow['digest_prev'][-1][:10]} " \
        f"{flow['digest'][:10]}: {GREEN}added{RESET}{CLREOL}")

def flow_remove(flow):
    flow_set.remove(flow['digest'])
    print(f"{flow['digest_prev'][-1][:10]} " \
        f"{flow['digest'][:10]}: {YELLOW}removed{RESET}{CLREOL}")

try:
    while True:
        L = F.readline()
        J = json.loads(L.strip())
        if 'length' not in J:
            print('malformed')
            sys.exit(1)

        L = F.read(J['length'])
        J = json.loads(L.strip())

        if 'type' not in J:
            print('malformed')
            sys.exit(1)

        if J['type'] == 'flow':
            print_flow(J['flow'], f'{GREEN}dpi_init (flow){RESET}')

            n_new += 1
            digest = J['flow']['digest']
            if digest in flow_set:
                n_dup += 1
                print(f"{RED}duplicate{RESET}: {J['flow']['digest']}")
            else:
                n_active += 1
                flow_add(J['flow'])

        elif J['type'] == 'flow_dpi_update':
            print_flow(J['flow'], f'{CYAN}dpi_update{RESET}')

            n_update += 1
            update_flow(J['flow'], 'dpi_update')

        elif J['type'] == 'flow_dpi_complete':
            print_flow(J['flow'], f'{MAGENTA}dpi_complete{RESET}')

            n_complete += 1
            update_flow(J['flow'], 'dpi_complete')

        elif J['type'] == 'flow_purge':
            print_flow(J['flow'], f'{YELLOW}purge{RESET}')

            n_purge += 1
            digest = J['flow']['digest']

            if digest in flow_set:
                n_active -= 1
                flow_remove(J['flow'])
            else:
                n_orphan += 1
                print_flow(J['flow'], f'{RED}purge{RESET}: orphaned')

        check = (n_complete - n_dup) - (n_purge - n_orphan)
        xtra = n_complete - n_purge

        print(f'NEW={GREEN}{n_new}{RESET} UPDATE={CYAN}{n_update}{RESET} ' \
            f'COMPLETE={MAGENTA}{n_complete}{RESET} PURGE={YELLOW}{n_purge}{RESET} ' \
            f'| ACTIVE={n_active} DUP={RED}{n_dup}{RESET} ' \
            f'ORPHAN={RED}{n_orphan}{RESET} | XTRA={xtra} ' \
            f'SIZE={len(flow_set)} (CHECK={check}){CLREOL}', end='\r')

except json.decoder.JSONDecodeError:
    print()
    print('[decode error]')
    sys.exit(1)
except KeyboardInterrupt:
    print()
    print('[interrupted]')
    sys.exit(0)

