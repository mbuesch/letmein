// -*- coding: utf-8 -*-
//
// Copyright (C) 2024-2025 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

#[no_mangle]
pub extern "C" fn Java_ch_bues_letmein_Letmein_init<'a>(
    mut env: JNIEnv<'a>,
    class: JClass<'a>,
    input: JString<'a>,
) -> jstring {
    let input: String = env.get_string(&input).unwrap().into();
    let output = env.new_string(format!("Hello, {}!", input)).unwrap();
    output.into_raw()
}

#[no_mangle]
pub extern "C" fn Java_ch_bues_letmein_Letmein_foo<'a>(mut env: JNIEnv<'a>, class: JClass<'a>) {}

// vim: ts=4 sw=4 expandtab
