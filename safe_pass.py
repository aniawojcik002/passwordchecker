from string import punctuation
from hashlib import sha1
from requests import Response, get
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,             # Minimum level to display
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# class Response:
#   def __init__(self, url: str) -> None:
#     self.url = url
#   def fetch(self) -> Response | None:
#     with get(f"{self.url}") as response:
#       return response.text.splitlines()


class HashHandler:
  URL = 'https://api.pwnedpasswords.com/range/'
  def __init__(self, password: str) -> None:
    self.password = password
    self.hashed_password = self._convert_to_hash()
    self.response_api = []
    
  def fetch(self) -> Response | None:
    with get(f"{self.URL}{self.hashed_password[:5]}") as response:
      response_api = response.text.splitlines() 
      return response_api

  def _convert_to_hash(self) -> list:
    return sha1(self.password.encode('utf-8')).hexdigest()

  def is_found(self) -> bool:
    self.response_api = self.fetch()
    found = []
    # for sublist in hash_list: 
    for i, item in enumerate(self.response_api):
      if self.hashed_password.upper() == f"{self.hashed_password[:5].upper()}{item.partition(":")[0]}":
        found.append(self.hashed_password)
        return True
    return False

class FileReader:
    def __init__(self, file_in: Path) -> None:
      self.file_in = file_in

    def read_file(self) -> list[str]:
      with open(self.file_in, 'r', encoding='utf-8') as fin:
         return [line.strip() for line in fin if line.strip()]
                        
class FileWriter:
    def __init__(self, file_out: str, text_to_write: str) -> None:
      self.file_out = file_out
      self.text_to_write = text_to_write

    def write_to_file(self) -> None:
      with open(self.file_out, 'w', encoding='utf-8') as fout:
        fout.write(self.text_to_write)

class PasswordValidator:
  def __init__(self, password: str) -> None:
    self.password = password

  def check_length(self) -> bool:
    return len(self.password) > 8

  def check_contain_number(self)-> bool:
    return any(char.isdigit for char in self.password)
      
  def check_contain_special_char(self)-> bool:
    return any(char in punctuation for char in self.password)

  def check_upper_lower(self)-> bool:
    has_upper = any(char.isupper() for char in self.password)
    has_lower = any(char.islower() for char in self.password)
    return has_upper and has_lower
  
  def validate(self) -> None:
    rules = [
      (self.check_length, "Za krótkie hasło"),
      (self.check_contain_number, "Nie zawiera numeru"),
      (self.check_contain_special_char, "Nie zawiera znaku specjalnego"),
      (self.check_upper_lower, "Nie zawiera małych lub dużych liter")
    ]

    errors = [msg for func, msg in rules if not func()]
    if errors:
      logging.warning("Password: %s | Errors: %s", self.password, ", ".join(errors))
    elif errors == []: 
      return None

def main():
  file = FileReader(Path('passwords.txt'))
  password_list = file.read_file()
  for password in password_list:
    PasswordValidator(password).validate()
    password_hash = HashHandler(password)
    found = password_hash.is_found()
    if found:
      logging.critical(password)

main()

