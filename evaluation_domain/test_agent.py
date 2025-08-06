#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简化的域名分析测试脚本
用于验证修复后的agent.py是否正常工作
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from agent import process_uncached_domain, test_llm_connection

def test_single_domain():
    """测试单个域名的分析"""
    print("="*60)
    print("开始测试域名分析功能")
    print("="*60)
    
    # 测试LLM连接
    test_llm_connection()
    
    # 测试一个简单的域名
    test_domain = "example.com"
    print(f"\n测试域名: {test_domain}")
    
    try:
        result = process_uncached_domain(test_domain)
        if result == "ERROR":
            print("❌ 测试失败：分析过程中发生错误")
            return False
        else:
            print("✅ 测试成功：域名分析完成")
            return True
    except Exception as e:
        print(f"❌ 测试失败：{e}")
        return False

if __name__ == "__main__":
    success = test_single_domain()
    if success:
        print("\n🎉 所有测试通过！")
    else:
        print("\n💥 测试失败，请检查错误信息")
        sys.exit(1) 