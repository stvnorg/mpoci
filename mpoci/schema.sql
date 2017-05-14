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
    update_by text not null,
    time_date text not null,
    notes text not null,
    admin_response text not null,
    merge_status text not null,
    revert_status text not null,
    review_status text not null
);

drop table if exists latest_merge;
create table latest_merge (
    id integer primary key autoincrement,
    activity_id integer not null,
    project_name text not null,
    branch_name text not null,
    merged_by text not null,
    merged_at text not null
);

drop table if exists projects;
create table projects (
  id integer primary key autoincrement,
  project_name text not null,
  description text not null,
  created_by text not null,
  created_at text not null
);
