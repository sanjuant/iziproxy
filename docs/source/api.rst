Référence de l'API
==================

Configuration en une ligne
--------------------------

.. autofunction:: iziproxy.install

.. autofunction:: iziproxy.uninstall

.. autofunction:: iziproxy.current

.. autoclass:: iziproxy.Installation
   :members: describe, uninstall

Classe principale
-----------------

.. autoclass:: iziproxy.IziProxy
   :members:
   :special-members: __enter__, __exit__

Proxy local
-----------

.. autoclass:: iziproxy.LocalProxy
   :members: url, running, start, stop

Exceptions
----------

.. autoexception:: iziproxy.NtlmAuthenticationError

Classes de support
------------------

.. autoclass:: iziproxy.SecurePassword
   :members:

.. autoclass:: iziproxy.SecureProxyConfig
   :members:

Modules internes
----------------

Ces modules ne font pas partie de l'API publique et peuvent évoluer.

.. automodule:: iziproxy.adapters
   :members:

.. automodule:: iziproxy.integrations.httpx_transport
   :members: IziHTTPXTransport, AsyncIziHTTPXTransport, build_client

.. automodule:: iziproxy.integrations.aiohttp_session
   :members:

.. automodule:: iziproxy.integrations.urllib3_pool
   :members:

.. automodule:: iziproxy.integrations.urllib_handler
   :members:

.. automodule:: iziproxy.integrations.http_client
   :members:

.. automodule:: iziproxy.integrations.tools
   :members:

.. automodule:: iziproxy.ntlm_auth
   :members:

.. automodule:: iziproxy.proxy_detector
   :members:

.. automodule:: iziproxy.pac_evaluator
   :members: create_evaluator, PacEvaluationError, PacTimeoutError, PAC_EVAL_TIMEOUT

.. automodule:: iziproxy.proxy_utils
   :members:

.. automodule:: iziproxy.tls_env
   :members: system_ca_bundle, tls_environment, cache_dir

.. automodule:: iziproxy.config_manager
   :members:

.. automodule:: iziproxy.env_detector
   :members:

.. automodule:: iziproxy.password_manager
   :members:

.. automodule:: iziproxy.logger
   :members:
