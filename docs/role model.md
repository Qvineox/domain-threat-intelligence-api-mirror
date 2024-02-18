# User role model

System uses permission based auth model, so every process has its oven defined role assigned to it.

<table>
  <tr>
    <td>ID</td>
    <td>Role name</td>
    <td>Description</td>
  </tr>
  <tr>
    <td colspan="3">Auth module</td>
  </tr>
<tr>
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
    <td colspan="3">Users module</td>
  </tr>
<tr>
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
    <td colspan="3">Blacklists module</td>
  </tr>
<tr>
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
    <td colspan="3">Configuration module</td>
  </tr>
<tr>
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

