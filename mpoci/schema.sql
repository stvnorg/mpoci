drop table if exists members;
create table members (
    id integer primary key autoincrement,
    name text not null,
    username text not null,
    password text not null,
    level text not null,
    time_date_added text not null
);

drop table if exists activity;
create table activity (
    id integer primary key autoincrement,
    project_name text not null,
    branch_name text not null,
    files_list text not null,
    updated_by text not null,
    updated_at text not null,
    notes text not null,
    admin_response text not null,
    merge_status integer not null,
    revert_status integer not null,
    review_status integer not null
);

drop table if exists merge_activity;
create table merge_activity (
    id integer primary key autoincrement,
    activity_id integer not null,
    project_name text not null,
    branch_name text not null,
    merged_by text not null,
    merged_at text not null
);

drop table if exists revert_activity;
create table revert_activity (
  id integer primary key autoincrement,
  activity_id integer not null,
  project_name text not null,
  branch_name text not null,
  reverted_by text not null,
  reverted_at text not null
);

drop table if exists projects;
create table projects (
  id integer primary key autoincrement,
  project_name text not null,
  description text not null,
  created_by text not null,
  created_at text not null,
  project_status integer not null
);
