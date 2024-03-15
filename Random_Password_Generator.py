import random

def generate_password(length, lowercase=True, uppercase=True, digits=True, symbols=True):
  """Generates a random password based on user-defined criteria.

  Args:
      length: The desired length of the password.
      lowercase: Include lowercase letters (True by default).
      uppercase: Include uppercase letters (True by default).
      digits: Include digits (True by default).
      symbols: Include symbols (True by default).

  Returns:
      A randomly generated password string.
  """

  # Define character sets based on user preferences
  lowercase_letters = 'abcdefghijklmnopqrstuvwxyz'
  uppercase_letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  digits = '0123456789'
  symbols = '!@#$%^&*()'

  char_set = ""
  # Use the passed arguments from the function call
  if lowercase:
    char_set += lowercase_letters
  if uppercase:
    char_set += uppercase_letters
  if digits:
    char_set += digits
  if symbols:
    char_set += symbols

  if not char_set:
    raise ValueError("At least one character set must be chosen (lowercase, uppercase, digits, or symbols).")

  # Use random.choices to generate random password with desired length
  password = ''.join(random.choices(char_set, k=length))
  return password

def main():
  """Prompts user for password length and character set preferences, generates password, and displays result."""

  while True:
    try:
      length = int(input("Enter desired password length (minimum 8 characters): "))
      if length < 8:
        raise ValueError("Password length must be at least 8 characters.")
      break
    except ValueError as e:
      print("Invalid input:", e)
      print("Please enter a positive integer greater than or equal to 8.")

  # Get user preferences for character sets (use the function arguments)
  include_lowercase = input("Include lowercase letters (y/n)? ").lower() == 'y'
  include_uppercase = input("Include uppercase letters (y/n)? ").lower() == 'y'
  include_digits = input("Include digits (y/n)? ").lower() == 'y'
  include_symbols = input("Include symbols (e.g., !@#$%^&*)? (y/n)? ").lower() == 'y'

  # Generate password based on user choices
  password = generate_password(length, include_lowercase, include_uppercase, include_digits, include_symbols)

  print(f"Your randomly generated password is: {password}")

if __name__ == "__main__":
  main()
