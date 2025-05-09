from django import template
from chatbot.rsa import rsa_decrypt
from chatbot.models import UserProfile
import logging

register = template.Library()
logger = logging.getLogger(__name__)

@register.filter
def decrypt(value, user):
    if not user or not user.is_authenticated:
        logger.warning("No authenticated user provided for decryption")
        return value
    try:
        profile = UserProfile.objects.get(user=user)
        private_key = profile.get_rsa_private_key()
        decrypted_value = rsa_decrypt(value, private_key)
        return decrypted_value
    except UserProfile.DoesNotExist:
        logger.warning(f"No UserProfile found for user {user.id}")
        return value
    except Exception as e:
        logger.error(f"Decryption failed for value {value}: {str(e)}")
        return value