| Worker Status | Description                                                                                    |
|:-------------:|:-----------------------------------------------------------------------------------------------|
| STARTING      | Set by the web application when a worker has been created in the database.                     |
| RUNNING       | Set by the worker when it starts.                                                              |
| FINISHED      | Set by the worker when it stops.                                                               |
| ERROR         | Set by the worker when it encounters an error. Also uses `send_error` to set an error message. |


| Run Status    | Description                                                                                    |
|:-------------:|:-----------------------------------------------------------------------------------------------|
| STARTING      | Set by the web application when a run in started.                                              |
| RUNNING       | Set by the web application when all workers have reported `RUNNING` or `ERROR`.                |
| STOPPING      | Set by the web application when a run is stopped by the user. Signals the workers to stop.     |
| FINISHED      | Set by the web application when all workers have reported `FINISHED` or `ERROR`.               |