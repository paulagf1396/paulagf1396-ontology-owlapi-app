# Sistema para la gestión y tratamiento dinámico de TI, anomalías y riesgos basado en ontologías

Este trabajo se encarga de desarrollar un sistema de ontologías. Para su desarrollo y pruebas se han utilizado los siguientes recursos, aunque pueden utilizarse otros recursos de sistema operativo:

  - Eclipse
  - Java 8
  - [Protégé](https://protege.stanford.edu/) - Protégé 5.5.0
  - Sistema Operativo Mac OS Catalina versión 10.15.5


### Configuración

#### Fichero config.txt

Este archivo se encarga de la configuración de los parámetros del sistema antes de iniciar su ejecución.

Contiene las rutas a cada uno de los ficheros necesarios.

##### ANOMALIES.SV.CONFIG
Fichero de configuración de los parámetros de anomalías. En este caso se define el parámetro SUSPICIOUS VALUE  a partir de los siguientes parámetros. Este parámtero es el que identifica anomalías similares y simboliza la probabilidad de que ocurra una amenaza.
> SUSPICIOUS.VALUE.UMBRAL
> SUSPICIOUS.VALUE.INTERVALO

UMBRAL es el valor mínimo a partir del cual una anomalía es susceptible de generar amenazas. 
INTERVALO es el valor con el que aumenta el valor del parámetro SUSPICIOUS VALUE.
El rango de estos valores implica la precisión del sistema.

##### ANOMALIES.BBDD.CONFIG
Fichero de entrada de los datos de anomalías.

##### STIX.ELEMENTS.CONFIG
Fichero de entrada de los datos de *threat intelligence*.

##### RISK.CALCULATION
Fichero de configuración de los parámetros para el cálculo del riesgo
> RISK.PENALIZATION.VALUE

Este parámetro se define en minutos y define la antigüedad máxima de las mediciones a tener en cuenta para realizar el cálculo del riesgo. Este valor penalizará los valores calculados con anterioridad en función de lo alejados que estén en el tiempo. Cuanto más alejado esté un valor menos repercusión tendrá en el cálculo.

##### ASSETS.CONFIG
Fichero de entrada de los datos de activos desde PILAR.
> Este fichero solo incluye la parte de identificación de activos y dependencias

##### ASSET.VALUATION
Fichero de entrada de los datos de activos de PILAR.
> Este fichero solo incluye la parte de valoración de activos

### Ejecución

Antes de la ejecución es necesario configurar adecuadamente las rutas correctas a los ficheros en la carpeta config-files en el fichero config.txt, así como los parámetros mencionados anteriormente.