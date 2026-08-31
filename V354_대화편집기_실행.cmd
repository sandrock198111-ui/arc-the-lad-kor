@echo off
chcp 65001 >nul
cd /d "%~dp0"
python "02_scripts\review_editor.py"
if errorlevel 1 (
  echo.
  echo V354 대화 편집기를 실행하지 못했습니다. 위 오류를 확인해 주세요.
  pause
)
