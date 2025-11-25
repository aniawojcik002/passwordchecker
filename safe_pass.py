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

class Response:
  def __init__(self, url: str) -> None:
    self.url = url

  def fetch(self) -> Response | None:
    with get(f"{self.url}") as response:
      return response.text.splitlines() 

class HashHandler:
  def __init__(self, hash_element: str, hashes_list: list) -> None:
    self.hash_element = hash_element
    self.hashes_list = hashes_list
  
  def convert_to_hash(self) -> list:
    return [sha1(element.encode('utf-8')).hexdigest() for element in self.hashes_list]

  def is_found(self) -> list:
    found = []
    for sublist in self.hashes_list: 
      for i, item in enumerate(sublist):
        if self.hash_element == f"{self.hash_element[:5].upper()}{item.partition(":")[0]}":
          found.append(self.hash_element)
    return found

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
  url = 'https://api.pwnedpasswords.com/range/'
  file = FileReader(Path('passwords.txt'))
  my_password_list = file.read_file()

  for password in my_password_list:
    PasswordValidator(password).validate()
    my_passwords_hashes = HashHandler(password, my_password_list).convert_to_hash()

  responses = []
  for element in my_passwords_hashes:
    response = Response(f"{url}{element[:5]}").fetch()
    responses.append(response)

  for i, element in enumerate(my_passwords_hashes):
    found = HashHandler(element.upper(), responses).is_found()
    if found:
      logging.critical(my_password_list[i])

main()

