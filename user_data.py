import re

from google.appengine.ext import db

import evelink
from evelink import appengine as elink_appengine
import models


class ApiKeyError(Exception):
  pass

class InvalidKeyError(ApiKeyError):
  pass


def get_keys_for_user(user):
  """Retrieves a list of models.APIKey instances for the given user."""
  keys = []
  for key in models.APIKey.all().filter("owner =", user):
    keys.append(key)
  return keys


def add_key_for_user(user, key_id, vcode):
  """Adds the given key_id/vcode to the given user.

  Args:
    user: the user object
    key_id: str or int, the key_id to add
    vcode: str, the vcode for the key
  Returns:
    True if the key didn't exist and was added, False if it already existed.
  """
  for key in get_keys_for_user(user):
    if key.key_id == key_id and key.vcode == vcode:
      return False

  new_key = models.APIKey(key_id=key_id, vcode=vcode, owner=user)
  new_key.put()
  return True


def remove_key_for_user(user, key_id):
  """Removes the given key_id from the given user.  Returns nothing."""
  user_keys = models.APIKey.all().filter("owner = ", user)
  existing_key = user_keys.filter("key_id =", key_id).get()
  if existing_key:
    existing_key.delete()


def validate_key(key_id):
  try:
    key_id = int(key_id)
    if not key_id > 0:
      raise ValueError()
    return key_id
  except (ValueError, TypeError):
    return None


def validate_vcode(vcode):
  if not vcode or not re.match(r'^[a-zA-Z0-9]{64}$', vcode):
    return None
  return vcode


def refresh_key_for_user(user, key_id):
  """Refreshes characters for the given key ID.

  Args:
    user: the user whose API keys we should use
    key_id: the key ID we should refresh

  Returns:
    True if the refresh succeeded, False if the key wasn't known
  Raises:
    ApiKeyError if an error occurs
  """
  user_keys = models.APIKey.all().filter("owner =", user)
  existing_key = user_keys.filter("key_id = ", key_id).get()

  if not existing_key:
    return False

  try:
    refresh_characters(existing_key)
  except evelink.api.APIError as e:
    raise ApiKeyError(e)

  return True


def refresh_characters(key):
  elink_api = elink_appengine.AppEngineAPI(api_key=(key.key_id, key.vcode))
  elink_account = evelink.account.Account(api=elink_api)
  info = elink_account.key_info()

  if not (info['access_mask'] & 8):
    raise InvalidKeyError('This key does not have Character Sheet access')

  retrieved_characters = info['characters']
  existing_characters = list(key.character_set)

  old_ids = set(c.char_id for c in existing_characters)
  new_ids = set(retrieved_characters)

  ids_to_delete = old_ids - new_ids
  ids_to_add = new_ids - old_ids

  models_to_add = []
  for char_id in ids_to_add:
    name = retrieved_characters[char_id]['name']
    model = models.Character(char_id=char_id, name=name, api_key=key)
    models_to_add.append(model)
  if models_to_add:
    db.put(models_to_add)

  models_to_delete = [c for c in existing_characters
    if c.char_id in ids_to_delete]
  if models_to_delete:
    db.delete(models_to_delete)

def get_characters_for_user(user):
  characters = []
  keys = models.APIKey.all().filter("owner =", user)
  for key in keys:
    characters.extend(key.character_set)
  characters.sort(key=lambda c:c.name)
  return characters

def find_character_by_id(char_id, characters):
  for char in characters:
    if char.char_id == char_id:
      return char

def get_character_sheet(character):
  key = character.api_key
  elink_api = elink_appengine.AppEngineAPI(api_key=(key.key_id, key.vcode))
  elink_char = evelink.char.Char(character.char_id, api=elink_api)
  return elink_char.character_sheet()
