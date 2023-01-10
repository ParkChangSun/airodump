#!/bin/bash

ifconfig wlx588694f394db down
ip link set wlx588694f394db name mon0
iwconfig mon0 mode monitor
ifconfig mon0 up