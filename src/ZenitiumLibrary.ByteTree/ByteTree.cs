/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)
Copyright (C) 2026  xRuffKez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading;

namespace ZenitiumLibrary.ByteTree
{
    public class ByteTree<TValue> : ByteTree<byte[], TValue> where TValue : class?
    {
        public ByteTree(int keySpace = 256)
            : base(keySpace)
        { }

        protected override byte[] ConvertToByteKey(byte[] key, bool throwException = true)
        {
            return key;
        }
    }

    public abstract class ByteTree<TKey, TValue> : IEnumerable<TValue?> where TValue : class?
    {
        #region variables

        protected readonly int _keySpace;
        protected readonly Node _root;

        #endregion

        #region constructor

        protected ByteTree(int keySpace)
        {
            if ((keySpace < 0) || (keySpace > 256))
                throw new ArgumentOutOfRangeException(nameof(keySpace));

            _keySpace = keySpace;
            _root = new Node(null, 0, _keySpace, null);
        }

        #endregion

        #region protected

        protected abstract byte[] ConvertToByteKey(TKey key, bool throwException = true);

        protected bool TryRemove(TKey key, out TValue? value, out Node? currentNode)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key, false);
            if (bKey is null)
            {
                value = default;
                currentNode = default;
                return false;
            }

            NodeValue? removedValue = _root.RemoveNodeValue(bKey, out currentNode);
            if (removedValue is null)
            {
                value = default;
                return false;
            }

            value = removedValue.Value;
            return true;
        }

        protected bool TryGet(TKey key, out TValue? value, out Node? currentNode)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key, false);
            if (bKey is null)
            {
                value = default;
                currentNode = default;
                return false;
            }

            NodeValue? nodeValue = _root.FindNodeValue(bKey, out currentNode);
            if (nodeValue is null)
            {
                value = default;
                return false;
            }

            value = nodeValue.Value;
            return true;
        }

        #endregion

        #region public

        public void Clear()
        {
            _root.ClearNode();
        }

        public void Add(TKey key, TValue? value)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            if (!_root.AddNodeValue(bKey, delegate () { return new NodeValue(bKey, value); }, _keySpace, out _, out _))
                throw new ArgumentException("Key already exists.");
        }

        public bool TryAdd(TKey key, TValue? value)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key, false);
            if (bKey is null)
            {
                value = default;
                return false;
            }

            return _root.AddNodeValue(bKey, delegate () { return new NodeValue(bKey, value); }, _keySpace, out _, out _);
        }

        public TValue? AddOrUpdate(TKey key, Func<TKey, TValue?> addValueFactory, Func<TKey, TValue?, TValue?> updateValueFactory)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            if (_root.AddNodeValue(bKey, delegate () { return new NodeValue(bKey, addValueFactory(key)); }, _keySpace, out NodeValue? addedValue, out NodeValue? existingValue))
                return addedValue!.Value;

            TValue? updateValue = updateValueFactory(key, existingValue!.Value);
            existingValue.Value = updateValue;
            return updateValue;
        }

        public TValue? AddOrUpdate(TKey key, TValue? addValue, Func<TKey, TValue?, TValue?> updateValueFactory)
        {
            return AddOrUpdate(key, delegate (TKey k) { return addValue; }, updateValueFactory);
        }

        public bool ContainsKey(TKey key)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key, false);
            if (bKey is null)
                return false;

            return _root.FindNodeValue(bKey, out _) is not null;
        }

        public bool TryGet(TKey key, out TValue? value)
        {
            return TryGet(key, out value, out _);
        }

        public TValue? GetOrAdd(TKey key, Func<TKey, TValue?> valueFactory)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            if (_root.AddNodeValue(bKey, delegate () { return new NodeValue(bKey, valueFactory(key)); }, _keySpace, out NodeValue? addedValue, out NodeValue? existingValue))
                return addedValue!.Value;

            return existingValue!.Value;
        }

        public TValue? GetOrAdd(TKey key, TValue? value)
        {
            return GetOrAdd(key, delegate (TKey k) { return value; });
        }

        public virtual bool TryRemove(TKey key, out TValue? value)
        {
            return TryRemove(key, out value, out _);
        }

        public bool TryUpdate(TKey key, TValue? newValue, TValue? comparisonValue)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key, false);
            if (bKey is null)
                return false;

            NodeValue? nodeValue = _root.FindNodeValue(bKey, out _);
            if (nodeValue is null)
                return false;

            return nodeValue.TryUpdateValue(newValue, comparisonValue);
        }

        public IEnumerator<TValue?> GetEnumerator()
        {
            return new ByteTreeEnumerator(_root, false);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return new ByteTreeEnumerator(_root, false);
        }

        public IEnumerable<TValue?> GetReverseEnumerable()
        {
            return new ByteTreeReverseEnumerable(_root);
        }

        #endregion

        #region properties

        public bool IsEmpty
        { get { return _root.IsEmpty; } }

        public TValue? this[TKey key]
        {
            get
            {
                if (key is null)
                    throw new ArgumentNullException(nameof(key));

                byte[] bKey = ConvertToByteKey(key);

                NodeValue? nodeValue = _root.FindNodeValue(bKey, out _);
                if (nodeValue is null)
                    throw new KeyNotFoundException();

                return nodeValue.Value;
            }
            set
            {
                AddOrUpdate(key, delegate (TKey k) { return value; }, delegate (TKey k, TValue? v) { return value; });
            }
        }

        #endregion

        protected sealed class Node
        {
            #region variables

            readonly Node? _parent;
            readonly int _depth;
            readonly byte _k;

            readonly Node[]? _children;
            volatile NodeValue? _value;

            #endregion

            #region constructor

            public Node(Node? parent, byte k, int keySpace, NodeValue? value)
            {
                if (parent is null)
                {
                    _depth = 0;
                    _k = 0;
                }
                else
                {
                    _parent = parent;
                    _depth = _parent._depth + 1;
                    _k = k;
                }

                if (keySpace > 0)
                    _children = new Node[keySpace];

                _value = value;

                if ((_children is null) && (_value is null))
                    throw new InvalidOperationException();
            }

            #endregion

            #region private

            private static bool KeyEquals(int startIndex, byte[] key1, byte[] key2)
            {
                if (key1.Length != key2.Length)
                    return false;

                for (int i = startIndex; i < key1.Length; i++)
                {
                    if (key1[i] != key2[i])
                        return false;
                }

                return true;
            }

            #endregion

            #region public

            public bool AddNodeValue(byte[] key, Func<NodeValue> newValue, int keySpace, out NodeValue? addedValue, out NodeValue? existingValue)
            {
                Node current = this;

                do
                {
                    while (current._depth < key.Length)
                    {
                        if (current._children is null)
                            break;

                        byte k = key[current._depth];
                        Node child = Volatile.Read(ref current._children[k]);
                        if (child is null)
                        {
                            Node addNewNode = new Node(current, k, 0, newValue());
                            Node originalChild = Interlocked.CompareExchange(ref current._children[k], addNewNode, null);
                            if (originalChild is null)
                            {
                                addedValue = addNewNode._value;
                                existingValue = null;
                                return true;
                            }

                            child = originalChild;
                        }

                        current = child;
                    }

                    NodeValue? value = current._value;

                    if ((value is not null) && KeyEquals(current._depth, value.Key, key))
                    {
                        addedValue = null;
                        existingValue = value;
                        return false;
                    }
                    else
                    {
                        if ((current._children is null) && (value is not null))
                        {
                            Node stemNode;

                            if (value.Key.Length == current._depth)
                            {
                                stemNode = new Node(current._parent, current._k, keySpace, value);
                            }
                            else
                            {
                                stemNode = new Node(current._parent, current._k, keySpace, null);

                                byte k = value.Key[current._depth];
                                stemNode._children![k] = new Node(stemNode, k, 0, value);
                            }

                            if ((current._parent is null) || (current._parent._children is null))
                            {
                                current = this;
                            }
                            else
                            {
                                Node originalNode = Interlocked.CompareExchange(ref current._parent._children[current._k], stemNode, current);
                                if (ReferenceEquals(originalNode, current))
                                {
                                    current = stemNode;
                                }
                                else
                                {
                                    if (originalNode is null)
                                    {
                                        current = this;
                                    }
                                    else
                                    {
                                        current = originalNode;
                                    }
                                }
                            }
                        }
                        else
                        {
                            NodeValue addNewValue = newValue();
                            NodeValue? originalValue = Interlocked.CompareExchange(ref current._value, addNewValue, value);
                            if (ReferenceEquals(originalValue, value))
                            {
                                addedValue = addNewValue;
                                existingValue = null;
                                return true;
                            }

                            if (originalValue is not null)
                            {
                                addedValue = null;
                                existingValue = originalValue;
                                return false;
                            }
                        }
                    }
                }
                while (true);
            }

            public NodeValue? FindNodeValue(byte[] key, out Node currentNode)
            {
                currentNode = this;

                while (currentNode._depth < key.Length)
                {
                    if (currentNode._children is null)
                        break;

                    Node child = Volatile.Read(ref currentNode._children[key[currentNode._depth]]);
                    if (child is null)
                        return null;

                    currentNode = child;
                }

                NodeValue? value = currentNode._value;

                if ((value is not null) && KeyEquals(currentNode._depth, value.Key, key))
                    return value;

                return null;
            }

            public NodeValue? RemoveNodeValue(byte[] key, out Node currentNode)
            {
                currentNode = this;

                do
                {
                    while (currentNode._depth < key.Length)
                    {
                        if (currentNode._children is null)
                            break;

                        Node child = Volatile.Read(ref currentNode._children[key[currentNode._depth]]);
                        if (child is null)
                            return null;

                        currentNode = child;
                    }

                    NodeValue? value = currentNode._value;

                    if ((value is not null) && KeyEquals(currentNode._depth, value.Key, key))
                    {
                        if (currentNode._children is null)
                        {
                            if ((currentNode._parent is null) || (currentNode._parent._children is null))
                                return null;

                            Node? originalNode = Interlocked.CompareExchange(ref currentNode._parent._children[currentNode._k]!, null, currentNode);
                            if (ReferenceEquals(originalNode, currentNode))
                                return value;

                            if (originalNode is null)
                            {
                                return null;
                            }
                            else
                            {
                                currentNode = originalNode;
                            }
                        }
                        else
                        {
                            NodeValue? originalValue = Interlocked.CompareExchange(ref currentNode._value, null, value);
                            if (ReferenceEquals(originalValue, value))
                                return value;

                            return null;
                        }
                    }
                    else
                    {
                        return null;
                    }
                }
                while (true);
            }

            public void CleanThisBranch()
            {
                Node current = this;

                while (current._parent is not null)
                {
                    if (current._children is null)
                    {
                    }
                    else
                    {
                        if (!current.IsEmpty)
                            return;

                        if (current._parent._children is not null)
                            Volatile.Write(ref current._parent._children[current._k]!, null);
                    }

                    current = current._parent;
                }
            }

            public void ClearNode()
            {
                _value = null;

                if (_children is not null)
                {
                    for (int i = 0; i < _children.Length; i++)
                        Volatile.Write(ref _children[i]!, null);
                }
            }

            public Node? GetNextNodeWithValue(int baseDepth)
            {
                int k = 0;
                Node? current = this;

                while ((current is not null) && (current._depth >= baseDepth))
                {
                    if (current._children is not null)
                    {
                        Node? child = null;

                        for (int i = k; i < current._children.Length; i++)
                        {
                            child = Volatile.Read(ref current._children[i]);
                            if (child is not null)
                            {
                                if (child._value is not null)
                                    return child;

                                if (child._children is not null)
                                    break;
                            }
                        }

                        if (child is not null)
                        {
                            k = 0;
                            current = child;
                            continue;
                        }
                    }

                    k = current._k + 1;
                    current = current._parent;
                }

                return null;
            }

            public Node? GetLastNodeWithValue()
            {
                Node? lastNode = null;
                Node current = this;

                while (true)
                {
                    if (current._value is not null)
                        lastNode = current;

                    if (current._children is null)
                        break;

                    for (int i = current._children.Length - 1; i > -1; i--)
                    {
                        Node child = Volatile.Read(ref current._children[i]);
                        if (child is not null)
                        {
                            current = child;
                            break;
                        }
                    }
                }

                return lastNode;
            }

            public Node? GetPreviousNodeWithValue(int baseDepth)
            {
                int k = _k - 1;
                Node? current = _parent;

                while ((current is not null) && (current._depth >= baseDepth))
                {
                    if (current._children is not null)
                    {
                        Node? child = null;

                        for (int i = k; i > -1; i--)
                        {
                            child = Volatile.Read(ref current._children[i]);
                            if (child is not null)
                            {
                                if (child._children is not null)
                                    break;

                                if (child._value is not null)
                                    return child;
                            }
                        }

                        if (child is not null)
                        {
                            k = current._children.Length - 1;
                            current = child;
                            continue;
                        }
                    }

                    if (current._value is not null)
                        return current;

                    k = current._k - 1;
                    current = current._parent;
                }

                return null;
            }

            #endregion

            #region properties

            public Node? Parent
            { get { return _parent; } }

            public int Depth
            { get { return _depth; } }

            public byte K
            { get { return _k; } }

            public Node[]? Children
            { get { return _children; } }

            public NodeValue? Value
            { get { return _value; } }

            public bool IsEmpty
            {
                get
                {
                    if (_value is not null)
                        return false;

                    if (_children is not null)
                    {
                        for (int i = 0; i < _children.Length; i++)
                        {
                            if (Volatile.Read(ref _children[i]) is not null)
                                return false;
                        }
                    }

                    return true;
                }
            }

            public bool HasChildren
            {
                get
                {
                    if (_children is null)
                        return false;

                    for (int i = 0; i < _children.Length; i++)
                    {
                        if (Volatile.Read(ref _children[i]) is not null)
                            return true;
                    }

                    return false;
                }
            }

            #endregion
        }

        protected sealed class NodeValue
        {
            #region variables

            readonly byte[] _key;
            TValue? _value;

            #endregion

            #region constructor

            public NodeValue(byte[] key, TValue? value)
            {
                _key = key;
                _value = value;
            }

            #endregion

            #region public

            public bool TryUpdateValue(TValue? newValue, TValue? comparisonValue)
            {
                TValue? originalValue = Interlocked.CompareExchange(ref _value, newValue, comparisonValue);
                return ReferenceEquals(originalValue, comparisonValue);
            }

            public override string ToString()
            {
                return Convert.ToHexString(_key).ToLowerInvariant() + ": " + (_value?.ToString() ?? "null");
            }

            #endregion

            #region properties

            public byte[] Key
            { get { return _key; } }

            public TValue? Value
            {
                get { return _value; }
                set { _value = value; }
            }

            #endregion
        }

        private sealed class ByteTreeReverseEnumerable : IEnumerable<TValue?>
        {
            #region variables

            readonly Node _root;

            #endregion

            #region constructor

            public ByteTreeReverseEnumerable(Node root)
            {
                _root = root;
            }

            #endregion

            #region public

            public IEnumerator<TValue?> GetEnumerator()
            {
                return new ByteTreeEnumerator(_root, true);
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return new ByteTreeEnumerator(_root, true);
            }

            #endregion
        }

        protected sealed class ByteTreeEnumerator : IEnumerator<TValue?>
        {
            #region variables

            readonly Node _root;
            readonly bool _reverse;

            Node? _current;
            NodeValue? _value;
            bool _finished;

            #endregion

            #region constructor

            public ByteTreeEnumerator(Node root, bool reverse)
            {
                _root = root;
                _reverse = reverse;
            }

            #endregion

            #region public

            public void Dispose()
            {
            }

            public TValue? Current
            {
                get
                {
                    if (_value is null)
                        return default;

                    return _value.Value;
                }
            }

            object? IEnumerator.Current
            {
                get
                {
                    if (_value is null)
                        return default;

                    return _value.Value;
                }
            }

            public void Reset()
            {
                _current = null;
                _value = null;
                _finished = false;
            }

            public bool MoveNext()
            {
                if (_finished)
                    return false;

                if (_current is null)
                {
                    if (_reverse)
                    {
                        _current = _root.GetLastNodeWithValue();
                        if (_current is null)
                        {
                            _value = null;
                            _finished = true;
                            return false;
                        }
                    }
                    else
                    {
                        _current = _root;
                    }

                    NodeValue? value = _current.Value;
                    if (value is not null)
                    {
                        _value = value;
                        return true;
                    }
                }

                do
                {
                    if (_reverse)
                        _current = _current.GetPreviousNodeWithValue(_root.Depth);
                    else
                        _current = _current.GetNextNodeWithValue(_root.Depth);

                    if (_current is null)
                    {
                        _value = null;
                        _finished = true;
                        return false;
                    }

                    NodeValue? value = _current.Value;
                    if (value is not null)
                    {
                        _value = value;
                        return true;
                    }
                }
                while (true);
            }

            #endregion
        }
    }
}
