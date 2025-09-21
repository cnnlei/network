#!/bin/bash
while true
do
  echo "启动Go转发服务..."
  go run .
  echo "服务已退出（可能是通过API重启），将在1秒后重启..."
  sleep 1
done
