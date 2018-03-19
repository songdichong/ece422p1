drop table if exists customers;
create table customers (
  cid            text,
  group_name    text,
  pwd            blob,
  public_key     blob,
  private_key    blob,
  primary key (cid));

drop table if exists permissions;
create table permissions(
  shareto        text,
  sharefrom      text,
  filepath       text,
  permission     text,
  signature      blob,
  primary key (shareto, sharefrom, filepath));

drop table if exists files;
create table files (
  filepath      text,
  filekey       blob,
  filehash      blob,
  primary key (filepath));

drop table if exists dirs;
create table dirs (
  dirpath      text,
  dirhash      blob,
  primary key (dirpath));
