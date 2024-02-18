# Ролевая модель системы

Система использует модель авторизации, основанную на привилегиях/разрешениях (permission), поэтому каждому процессу
назначается своя определенная
привилегия.

<table>
  <tr>
    <td>Группа</td>
    <td>ID разрешения</td>
    <td>Имя разрешения</td>
    <td>Описание</td>
</tr>
<tr>
    <td colspan="4">Auth module</td>
</tr>
<tr>
    <td rowspan="2">Auth <br> <i>(1xxx)</i> </td>
    <td>1001</td>
    <td>auth::login</td>
    <td>Возможность входа в систему</td>
</tr>
<tr>
    <td>1002</td>
    <td>auth::admin</td>
    <td>Администратор</td>
</tr>
<tr>
    <td colspan="4">Users module</td>
</tr>
<tr>
    <td rowspan="4">Users <br> <i>(2xxx)</i> </td>
    <td>2001</td>
    <td>users::view</td>
    <td>Просмотр списка пользователей</td>
</tr>
<tr>
    <td>2002</td>
    <td>users::register</td>
    <td>Регистрация новых пользователей</td>
</tr>
<tr>
<tr>
    <td>2003</td>
    <td>users::modify</td>
    <td>Изменение списка пользователей</td>
</tr>
<tr>
    <td colspan="4">Network map module</td>
</tr>
<tr>
    <td rowspan="2">Network map <br> <i>(3xxx)</i> </td>
    <td>3001</td>
    <td>network_map::view</td>
    <td>Просмотр карты сети</td>
</tr>
<tr>
    <td>3002</td>
    <td>network_map::modify</td>
    <td>Изменение карты сети</td>
</tr>
<tr>
    <td colspan="4">Blacklists module</td>
</tr>
<tr>
    <td rowspan="4">Blacklists <br> <i>(4xxx)</i> </td>
    <td>4001</td>
    <td>blacklists::view</td>
    <td>Просмотр списка блокировок</td>
</tr>
<tr>
    <td>4002</td>
    <td>blacklists::modify</td>
    <td>Изменение списка блокировок</td>
</tr>
<tr>
    <td>4003</td>
    <td>blacklists::import</td>
    <td>Импорт блокировок</td>
</tr>
<tr>
    <td>4004</td>
    <td>blacklists::export</td>
    <td>Экспорт блокировок</td>
</tr>
<tr>
    <td colspan="4">Scanning module</td>
</tr>
<tr>
    <td rowspan="8">Jobs <br> <i>(50xx)</i> </td>
    <td>5001</td>
    <td>scanning::jobs::execute</td>
    <td>Запуск задач сканирования</td>
</tr>
<tr>
    <td>5002</td>
    <td>scanning::jobs::oss</td>
    <td>Запуск OSS сканирования (открытые источники)</td>
</tr>
<tr>
    <td>5003</td>
    <td>scanning::jobs::nmap</td>
    <td>Запуск сканирования NMAP</td>
</tr>
<tr>
    <td>5004</td>
    <td>scanning::jobs::allow_homebound</td>
    <td>Запуск сканирования с домашних агентов</td>
</tr>
<tr>
    <td>5005</td>
    <td>scanning::jobs::allow_aggressive</td>
    <td>Запуск сканирования с агрессивными настройками</td>
</tr>
<tr>
    <td>5006</td>
    <td>scanning::jobs::view</td>
    <td>Просмотр задач сканирования</td>
</tr>
<tr>
    <td>5007</td>
    <td>scanning::jobs::modify</td>
    <td>Изменение задач сканирования</td>
</tr>
<tr>
    <td>5008</td>
    <td>scanning::jobs::terminate</td>
    <td>Прерывание задач сканирования</td>
</tr>
<tr>
    <td rowspan="2">Reports <br> <i>(51xx)</i> </td>
    <td>5101</td>
    <td>scanning::reports::view</td>
    <td>Просмотр результатов сканирования</td>
</tr>
<tr>
    <td>5102</td>
    <td>scanning::reports::modify</td>
    <td>Изменение результатов сканирования</td>
</tr>
<tr>
    <td rowspan="2">Agents <br> <i>(52xx)</i> </td>
    <td>5201</td>
    <td>scanning::agents::view</td>
    <td>Просмотр агентов сканирования</td>
</tr>
<tr>
    <td>5202</td>
    <td>scanning::agents::modify</td>
    <td>Изменение агентов сканирования</td>
</tr>
<tr>
    <td colspan="4">Configuration module</td>
</tr>
<tr>
    <td rowspan="3">Dynamic <br> <i>(60xx)</i> </td>
    <td>6001</td>
    <td>config::view</td>
    <td>Просмотр конфигурации платформы</td>
</tr>
<tr>
    <td>6002</td>
    <td>config::modify</td>
    <td>Изменение конфигурации платформы</td>
</tr>
<tr>
    <td>6003</td>
    <td>config::reset</td>
    <td>Сброс конфигурации платформы</td>
</tr>
</table>

