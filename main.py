"""
This is a simple single-file python program that can find basic XSS (cross-site scripting) vulnerabilities in a target url. Most XSS discovery tools use a payload refelection strategy in which payloads are injected in url parameters and the GET response is inspected for places where the payload content is reflected. This is a very low precision XSS detection strategy because most reflection does not support execution.

This program uses a different approach, and instead opens the target url in a browser, tests `alert(...)` payloads directly in the browser context, and listens for an alert being triggered. This means that any XSS spotted by this program is extremely unlikely to be a false positive. 

This program can be used with the command
```
  python main.py \
    --target_url "https://xss-game.appspot.com/level1/frame?query=test" \
    --payload_list_file_path lists/xss_payloads_with_alert_message_signal.txt
```
"""


import argparse
from typing import Any, Callable, Dict, List, Optional, Set
import asyncio
import logging
from copy import deepcopy
from dataclasses import dataclass

import urllib.parse
import numpy as np

import playwright
from playwright.async_api import async_playwright
from playwright._impl._page import Page
from playwright_stealth import stealth_async
from playwright.async_api import PlaywrightContextManager


async def wait_for_load_state_safe(page: Page, **kwargs):
  """
  A wrapper for the page.wait_for_load_state function that catches any exceptions that are thrown. This is useful because the page.wait_for_load_state function will throw an exception if the load state is not reached within the timeout. This is not fatal for our purposes, so we catch the exception and continue.
  """
  try:
    await page.wait_for_load_state(**kwargs)
  except playwright._impl._errors.Error as e:
    logging.error(f"[wait_for_load_state_safe] Error in page.wait_for_load_state(): {e}")
    pass

async def scroll_page_and_wait(page: Page, timeout: int = 500):
  """
  Given a page that has just been loaded, scroll to the top of the page and wait for the page to load (including all network calls). This is useful because some pages will only load certain elements when the page is scrolled.
  """

  # First wait for any post-open actions to occur
  await wait_for_load_state_safe(page, state='networkidle', timeout=5000)
  await page.wait_for_timeout(timeout)

  # Then scroll to the top of the page
  try:
    await page.evaluate(f"window.scrollTo(0, 0)")
  except playwright._impl._errors.Error as e:
    logging.error(f"[scroll_page_and_wait] Error in window.scrollTo(0, 0): {e}")

  # Wait for any post-scroll actions to occur
  await wait_for_load_state_safe(page, state='networkidle', timeout=5000)
  await page.wait_for_timeout(timeout)

class DialogListener:
  """
  A simple utility for capturing dialog messages that are displayed when a page is opened. This is useful for capturing alerts that are triggered by XSS payloads.
  """

  # Stores the message on each dialog
  dialog_message_log: Optional[List[str]]

  def __init__(self, page: Page):
    self.dialog_message_log = []

    self.page = page
    self.page.on("dialog", self.handle_dialog)

  async def handle_dialog(self, dialog):
    # Record the message on each dialog that is opened
    self.dialog_message_log.append(dialog.message)
    try:
      await dialog.dismiss()
    except playwright._impl._errors.Error as e:
      # If the dialog self-dismisses, then we expect to see an error. This shouldn't be fatal.
      logging.error(f"[Listener.handle_dialog] Error in dialog.dismiss(): {e}")

  def remove_listener(self):
    self.page.remove_listener("dialog", self.handle_dialog)

async def open_url_and_capture_dialog_messages(
  page: Page,
  url: str,
  timeout: int = 3000
) -> List[str]:
  """
  This function opens a url and captures the dialog messages that are displayed. This is useful for capturing alerts that are triggered by XSS payloads.
  Args:
    page: The playwright page
    url: The url to open
    timeout: The timeout in milliseconds
  Returns:
    The list of dialog messages that were displayed
  """

  # Add a listener that captures dialog messages
  dialog_listener = DialogListener(page=page)

  # Open the url
  await page.goto(url)

  # Wait for the page to load
  await scroll_page_and_wait(page=page, timeout=timeout)

  # Remove the listener
  dialog_listener.remove_listener()

  return dialog_listener.dialog_message_log

async def initialize_browser_context(
  playwright: PlaywrightContextManager,
  headless: bool = True,
  proxy_url: Optional[str] = None,
  storage_state: Optional[str] = None
) -> tuple:
  """
  Initialize a browser context with the given playwright instance
  Args:
    playwright: The playwright instance
    headless: Whether to run the browser in headless mode
    proxy_url: The proxy url to use. If None, we don't use a proxy
    storage_state: The storage state to use. If None, we don't use a storage state
  Returns:
    The browser and context
  """
  
  if proxy_url is not None:
    # We need to ignore https errors when we run playwright through a proxy
    browser = await playwright.chromium.launch(headless=headless, proxy={"server": proxy_url})
    context = await browser.new_context(ignore_https_errors=True, storage_state=storage_state)
  else:
    browser = await playwright.chromium.launch(headless=headless)
    context = await browser.new_context(storage_state=storage_state)
  return browser, context

@dataclass
class PlaywrightPageManager:
  """
  Wrapper around Playwright that manages a particular page and context
  """

  # The playwright instance
  playwright: "Playwright"

  # The browser itself (chromium by default)
  browser: "BrowserType"

  # The browser context, which stores cookies, local storage, etc
  context: "BrowserContext"

  # The page that we are interacting with
  page: "Page"

  # Whether the browser is running in headless mode
  headless: bool = True

  # The proxy url to use. If None, we don't use a proxy
  proxy_url: Optional[str] = None

  @classmethod
  async def prepare_page(cls, page: Page):
    # Apply some basic obfuscations to the browser to avoid bot detection
    await stealth_async(page)

  @classmethod
  async def construct(
    cls,
    headless: bool = True,
    proxy_url: Optional[str] = None
  ) -> "PlaywrightPageManager":
    """
    Construct a new PlaywrightPageManager with a new browser context
    Args:
      headless: Whether to run the browser in headless mode
      proxy_url: The proxy url to use. If None, we don't use a proxy
    Returns:
      The PlaywrightPageManager
    """
    
    playwright = await async_playwright().start()
    browser, context = await initialize_browser_context(playwright=playwright, headless=headless, proxy_url=proxy_url)
    page = await context.new_page()

    # This is a hack we use only for DVWA to control the security level. This doesn't apply to anything outside of DVWA accessed through localhost.
    await context.add_cookies([
      {'name': 'security',
      'value': 'medium',
      'domain': 'localhost',
      'path': '/',
      'expires': -1,
      'httpOnly': True,
      'secure': False,
      'sameSite': 'Lax'
    }])
    await cls.prepare_page(page=page)
    return cls(
      playwright=playwright,
      browser=browser,
      context=context,
      page=page,
      headless=headless,
      proxy_url=proxy_url
    )

  @classmethod
  async def from_storage_state(
    cls,
    storage_state: str,
    headless: bool = True,
    proxy_url: Optional[str] = None
  ) -> "PlaywrightPageManager":
    """
    Construct a new PlaywrightPageManager based on a storage_stage. This is useful for persisting authentication state across browsers. This is based on https://playwright.dev/python/docs/api-testing#reuse-authentication-state.

    Args:
      storage_state: The storage state to use
      headless: Whether to run the browser in headless mode
      proxy_url: The proxy url to use. If None, we don't use a proxy
    Returns:
      The PlaywrightPageManager
    """
    playwright = await async_playwright().start()
    browser, context = await initialize_browser_context(
      playwright=playwright,
      storage_state=storage_state,
      headless=headless,
      proxy_url=proxy_url)
    page = await context.new_page()

    await cls.prepare_page(page=page)
    return cls(
      playwright=playwright,
      browser=browser,
      context=context,
      page=page,
      headless=headless,
      proxy_url=proxy_url
    )

  async def clone(self) -> "PlaywrightPageManager":
    """
    Create a new PlaywrightPageManager with the same browser context data
    """
    storage_state = await self.context.storage_state()
    
    return await PlaywrightPageManager.from_storage_state(
      storage_state=storage_state,
      headless=self.headless,
      proxy_url=self.proxy_url
    )

  async def close(self) -> None:
    """
    Close all the resources associated with the PlaywrightPageManager
    """
    await self.page.close()
    await self.context.close()
    await self.browser.close()
    await self.playwright.stop()
  


class PlaywrightPageManagerCloneContext:
  """
  A simple utility for cloning a browser state (i.e. local storage, cookies, etc), opening a new browser with the same state, and cleanly closing the new browser once the task is done. This is useful for testing multiple urls with the same browser state.

  The usage pattern is
    ```
    async with PlaywrightPageManagerCloneContext(playwright_page_manager) as cloned_playwright_page_manager:
      # do stuff
    ```
  and this will guarantee that the cloned_playwright_page_manager will be closed once the block is exited.
  """

  def __init__(self, base_playwright_page_manager: PlaywrightPageManager):
    self.base_playwright_page_manager = base_playwright_page_manager

  async def __aenter__(self):
    self.cloned_playwright_page_manager = await self.base_playwright_page_manager.clone()
    return  self.cloned_playwright_page_manager

  async def __aexit__(self, *args):
    await self.cloned_playwright_page_manager.close()




def get_param_list(target_url: str) -> Dict[str, str]:
  """
  Get a dictionary of the parameters in the url
  """
  parsed_url = urllib.parse.urlparse(target_url)

  # Extract the query parameters
  param_list = urllib.parse.parse_qs(parsed_url.query)

  # Convert list values to single values if needed
  param_list = {k: v if len(v) > 1 else v[0] for k, v in param_list.items()}

  return param_list


def load_payload_list(payload_list_file_path: str, max_payload_count: Optional[int] = None) -> List[str]:
  """
  Load the list of payloads from the payload list file and return the list of payloads
  Args:
    payload_list_file_path: The path to the file containing the list of payloads
    max_payload_count: The maximum number of payloads to use from the payload list. If None, all payloads are used
  Returns:
    The list of payloads
  """
  with open(payload_list_file_path) as f:

    # Load the payload list and shuffle it
    payload_list = list(np.random.permutation([l.strip() for l in f.readlines()]))
    if max_payload_count is not None:
      payload_list = payload_list[:max_payload_count]

    # Double the size of the payload list by adding the url encoded version of each payload. Some payload lists will include payloads that are already url encoded, so we want to add both the original and the encoded version. This makes this program more resilient to payload lists provided in different formats.
    payload_list += [ urllib.parse.quote(p) for p in payload_list]
  return payload_list


def get_url_list(
  target_url: str,
  payload_list_file_path: str,
  max_payload_count: Optional[int] = None
) -> List[str]:
  """
  Given a target url, extract the parameters and generate a list of urls that are copies of this url except each parameter is replaced with a payload. Only one parameter is replaced at a time.

  Args:
    target_url: The target url
    payload_list_file_path: The path to the file containing the list of payloads
    max_payload_count: The maximum number of payloads to use from the payload list. If None, all payloads are used
  Returns:
    A list of urls with payloads
  """
  if not urllib.parse.urlparse(target_url).query:
    raise ValueError(f"The url {target_url} does not contain query parameters")

  # Get the list of payloads
  payload_list = load_payload_list(
    payload_list_file_path=payload_list_file_path,
    max_payload_count=max_payload_count
  )

  # Generate the list of urls
  base_url = target_url.split('?')[0]
  param_list = get_param_list(target_url=target_url)
  url_list = []
  for param in param_list:

    # We inject each payload into each parameter
    for payload in payload_list:
      params_copy = deepcopy(param_list)
      params_copy[param] = payload
      url_list.append(f"{base_url}?{urllib.parse.urlencode(params_copy)}")
  return url_list


async def get_dialog_message_set(playwright_page_manager: PlaywrightPageManager, url: str) -> Set[str]:
  """
  Get the set of dialog messages displayed when opening the url
  """

  # Clone the browser state (cookies etc) and open up a new browser with an identical state. This is useful if we've performed some set of user actions or initalized the browser from a particular state.
  async with PlaywrightPageManagerCloneContext(playwright_page_manager) as cloned_playwright_page_manager:
    dialog_message_set = set(await open_url_and_capture_dialog_messages(page=cloned_playwright_page_manager.page, url=url))
  logging.info(f"[get_dialog_message_set] url: {url} dialog_message_set: {dialog_message_set}")
  return dialog_message_set


async def get_first_url_that_triggers_non_default_dialog(
  target_url: str,
  playwright_page_manager: PlaywrightPageManager,
  payload_list_file_path: str,
  parallelism: int = 10,
  max_payload_count: Optional[int] = None
) -> Optional[str]:
  """
  Given a url and a list of payloads, extract the parameters from the url and try each payload on each parameter, and check what alerts are triggered.
  
  Args:
    target_url: The target url
    playwright_page_manager: The initialized PlaywrightPageManager
    payload_list: The list of payloads to use
    parallelism: The number of simultaneous requests to make
    max_payload_count: The maximum number of payloads to use from the payload list. If None, all payloads in payload_list_file_path are used
  Returns:
    The url that triggered the alert. None if no alert was triggered
  """

  # The payloads we have injected will open up a dialog box if successful. In order to prevent false positives we need to identify if the target url opens up a dialog box by default. The default_dialog_set contains the dialog messages that are displayed when the target url is opened without any payloads.
  default_dialog_set = await get_dialog_message_set(playwright_page_manager=playwright_page_manager, url=target_url)
  logging.info(f"[get_payload_to_triggered_alert] Default dialog set: {default_dialog_set}")

  # Generate a list of urls with payloads injected. These are what we will use for testing.
  url_list = get_url_list(
    target_url=target_url,
    payload_list_file_path=payload_list_file_path,
    max_payload_count=max_payload_count
  )

  # Iterate through the payloads in chunks of size `parallelism`
  for i in range(0, len(url_list), parallelism):
    url_list_chunk = url_list[i:i + parallelism]

    # Asynchronously open each of the urls in the url_list_chunk and use playwright to capture any dialog messages that are displayed
    dialog_message_set_list = await asyncio.gather(*[
      get_dialog_message_set(playwright_page_manager=playwright_page_manager, url=url) for url in url_list_chunk
    ])

    # If any of the dialog_message_sets are not equal to the default_dialog_set, then we have successfully triggered an alert with XSS and we can return the url
    for url_with_payload, dialog_message_set in zip(url_list, dialog_message_set_list):
      filtered_dialog_message_set = [] if dialog_message_set is None else [msg for msg in dialog_message_set if msg not in default_dialog_set]

      if len(filtered_dialog_message_set) > 0:
        # XSS alert triggered! Return the url
        return url_with_payload

  # If we reach this point, then no alert was triggered
  return None



async def main(args):
  logging.getLogger('').setLevel(logging.INFO)

  """
  NOTE: This simply initializes a default PlaywrightPageManager with no predefined storage state. We can very easily modify this program to initialize the PlaywrightPageManager with any kind of browser-persisted authentication state. This would allow us to test XSS on web pages that sit behind an authentication wall. It is much easier to allow a browser to do this for us than to manage the authentication headers ourselves.
  """
  playwright_page_manager = await PlaywrightPageManager.construct(headless=True)

  if not urllib.parse.urlparse(args.target_url).query:
    raise ValueError(f"The url {args.target_url} does not contain query parameters")

  first_url_that_triggers_non_default_dialog = await get_first_url_that_triggers_non_default_dialog(
    target_url=args.target_url,
    playwright_page_manager=playwright_page_manager,
    payload_list_file_path=args.payload_list_file_path,
    max_payload_count=None if args.max_payload_count is None else int(args.max_payload_count),
    parallelism=int(args.parallelism)
  )
  logging.info(f"first_url_that_triggers_non_default_dialog: {first_url_that_triggers_non_default_dialog}")

if __name__ == "__main__":
  """
  python main.py \
    --target_url "https://xss-game.appspot.com/level1/frame?query=test" \
    --payload_list_file_path lists/xss_payloads_with_alert_message_signal.txt
  """

  parser = argparse.ArgumentParser(description="Scana target url  for XSS vulnerabilities")
  parser.add_argument("--target_url", help="The target url. This url is expected to be formatted like https://domain/path?<queryparams>. This script will try different XSS payloads in the <queryparams>.", required=True)
  parser.add_argument("--payload_list_file_path", help="The path to the file containing the list of payloads", required=True)
  parser.add_argument("--max_payload_count", help="The maximum number of payloads to use. If not provided then all payloads are used.", type=int, default=None)
  parser.add_argument("--parallelism", help="The number of simultaneous requests to make", type=int, default=10)

  args = parser.parse_args()

  asyncio.run(main(args=args))
