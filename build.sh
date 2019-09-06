#!/bin/bash

export gntp_pwd=Hyper123
export gntp_app=kata-agent
export gntp_server=172.16.87.1:23053
export gntp_title="֪ͨ"
export gntp_message="build kata-agent"

export BEGIN_TS=`date +%s`
time make
RLT=$?
export END_TS=`date +%s`

if [[ $RLT -eq 0 ]]; then
  gntp-send.exe -a $gntp_app -s $gntp_server -p $gntp_pwd $gntp_title "$gntp_message �ɹ�:) $((END_TS-BEGIN_TS)) ��"
else
  gntp-send.exe -a $gntp_app -s $gntp_server -p $gntp_pwd $gntp_title "$gntp_message ʧ��:) $((END_TS-BEGIN_TS)) ��"
  exit 1
fi

which upx
if [ $? -eq 0 ]; then
  upx kata-agent
fi

echo "copy kata-agent to /c/Users/admin/kata-agent.exe"
cp -rf kata-agent /c/Users/admin/kata-agent.exe

